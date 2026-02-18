#define _GNU_SOURCE 
#include <sched.h> 

#include <pcap.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "../include/protocol_headers.h"
#include <pthread.h>
#include "../include/aho_corasick.h"
#include "../include/flow_table.h"
#include "../include/monitor.h"
#include <string.h>
#include <stdatomic.h> 
#include <signal.h> 


// globals defined in monitor.h

engine_stats_t engine_metrics = { 
    .acc_packets = ATOMIC_VAR_INIT(0), 
    .acc_bytes = ATOMIC_VAR_INIT(0), 
    .acc_matches = ATOMIC_VAR_INIT(0), 
    .acc_drops = ATOMIC_VAR_INIT(0), 

    .current_mbps = ATOMIC_VAR_INIT(0.0),
    .current_pps = ATOMIC_VAR_INIT(0.0), 

    .lifetime_packets = ATOMIC_VAR_INIT(0),
    .lifetime_bytes = ATOMIC_VAR_INIT(0),
    .lifetime_matches = ATOMIC_VAR_INIT(0),
    .lifetime_drops = ATOMIC_VAR_INIT(0),


    .engine_active = ATOMIC_VAR_INIT(true), 

    .active_flows = ATOMIC_VAR_INIT(0), 
    .max_flow_capacity = FLOW_TABLE_SIZE * 8 // ie. each bucket has 8 slots 
};

alert_t alert_queue[MAX_ALERTS]; 
int alert_head = 0; 
int alert_tail = 0; 
pthread_mutex_t alert_lock = PTHREAD_MUTEX_INITIALIZER; 

// globals defined in aho-corasick.h

ACNode trie[MAX_STATES]; 
int state_count = 1;  

// globals defined in flow_table.h

flow_entry_t *flow_table[FLOW_TABLE_SIZE]; 
pthread_mutex_t flow_locks[NUM_FLOW_LOCKS]; 

// globals defined in protocol_headers.h

worker_queue_t *worker_queues = NULL; 

// globals defined in this file

pthread_t *worker_threads = NULL;

static volatile bool keep_running = true; 

pcap_t *handle = NULL; 



// declarations

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_payload(const u_char *payload, int len);
void worker_thread(void *arg);
void search_packet(packet_t *packet_info, flow_entry_t *flow); 

void insert_pattern(const char* pattern, int pattern_id); 
void build_failure_links();

uint32_t hash_5tuple(flow_key_t *key); 
flow_entry_t* find_or_create_flow(packet_t *packet); 
void cleanup_aged_flows(unsigned int timeout_seconds); 


void add_alert(int severity, const char *msg) { 
    pthread_mutex_lock(&alert_lock); 
    snprintf(alert_queue[alert_head].message, ALERT_MSG_LEN, "%s", msg); 
    alert_queue[alert_head].severity = severity; 
    alert_head = (alert_head + 1) % MAX_ALERTS; 
    if(alert_head == alert_tail) { 
        alert_tail = (alert_tail + 1) % MAX_ALERTS; // overwrite the oldest
    }
    pthread_mutex_unlock(&alert_lock); 
}



/** 
 * @brief Used to pin a thread to the specified CPU core id 
 * @param core_id CPU core number (starts from 0). Number of cores is machine specific. 
 */
void pin_thread_to_core(int core_id) { 
    cpu_set_t cpuset; 
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);

    pthread_t current_thread = pthread_self();
    if(pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset) != 0) { 
        fprintf(stderr, "Error setting thread affinity\n");
    }
} 



/** 
 * @brief Callback function invoked by pcap_loop for every captured packet. This function acts as a 
 *        producer in the multi-threaded design. It parses raw packet data to extract the payload, reserves 
 *        a slot in the ring buffer, and copies the data for worker threads to process later. 
 * 
 * @param args User defined arguments (not used in this case, set to NULL when calling pcap_loop())
 * @param header Metadata about the captured packet (timestamp, length, etc.)
 * @param packet Pointer to the raw packet data captured by pcap. This includes the Ethernet header, 
 *               IP header, TCP header, and payload. 
 */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    // unused 
    (void)args; 
    // (void) header; 

    // pps rate limiting 
    static long last_sec = 0; 
    static atomic_long current_sec_count = 0; 
    long now = header->ts.tv_sec; // use timestamp from pcap rather than time(NULL)

    if(now != last_sec) { 
        last_sec = now; 
        atomic_store(&current_sec_count, 0); 
    }

    if (atomic_load(&current_sec_count) >= GLOBAL_PPS_LIMIT) {
        atomic_fetch_add(&engine_metrics.acc_drops, 1);
        return; // DROP: Do not add to worker queues
    }

    atomic_fetch_add(&current_sec_count, 1);

    // const sniff_ethernet *eth = (sniff_ethernet*)(packet); 
    const sniff_ip *ip_header = (sniff_ip*)(packet + sizeof(sniff_ethernet));
    int size_ip = IP_HL(ip_header) * 4;
    if (size_ip < 20 || ip_header->ip_p != IPPROTO_TCP) return; // not a valid IP header or not TCP

    const sniff_tcp *tcp = (sniff_tcp*)(packet + sizeof(sniff_ethernet) + size_ip); 
    int size_tcp = TH_OFF(tcp) * 4; 
    int payload_offset = sizeof(sniff_ethernet) + size_ip + size_tcp; 
    int payload_len = ntohs(ip_header->ip_len) - size_ip - size_tcp;

    // populate the 5-tuple key
    flow_key_t key = {
        .src_ip = ip_header->ip_src.s_addr, 
        .dst_ip = ip_header->ip_dst.s_addr,
        .src_port = tcp->th_sport,
        .dst_port = tcp->th_dport,
        .protocol = ip_header->ip_p 
    }; 
    
    // get assigned worker using hash
    uint32_t hash = hash_5tuple(&key); 
    int worker_id = hash % NUM_WORKERS; 
    worker_queue_t *q = &worker_queues[worker_id]; 

    // reserve index in ring buffer to reduce lock holding time 
    pthread_mutex_lock(&q->lock);
    int next_head = (q->head + 1) % RING_SIZE;
    if(next_head == q->tail) { 
        pthread_mutex_unlock(&q->lock);
        atomic_fetch_add(&engine_metrics.acc_drops, 1); 
        return; // buffer is full, drop packet (TODO: implement better strategy for handling this)
    }

    packet_t *packet_info = &q->buffer[q->head]; 
    packet_info->length = payload_len; 
    packet_info->src_ip = ip_header->ip_src;
    packet_info->key = key; 
    packet_info->hash = hash; 
    
    if(payload_len > 0) { 
        memcpy(packet_info->data, packet + payload_offset, 
            (payload_len > MAX_PACKET_SIZE) ? MAX_PACKET_SIZE : payload_len); 
    }

    q->head = next_head; 
    pthread_mutex_unlock(&q->lock); 
    pthread_cond_signal(&q->cond);
}


/**
 * @brief Used too print specific information about the given payload. 
 *        This function is archived (no longer in use). 
 * 
 * @param payload Address of payload 
 * @param len Payload length 
 */
void print_payload(const u_char *payload, int len) {
    const u_char *ch = payload;
    printf("   ");
    for(int i = 0; i < len; i++) {
        if (isprint(*ch)) // If it's a readable character
            printf("%c", *ch);
        else
            printf("."); // If it's binary data
        ch++;
    }
    printf("\n");
}











/** 
 * @brief Input function for worker thread loop when calling pthread_create(). 
 *        Each worker thread will pin itself to the specified CPU core and then 
 *        continuously check the ring buffer for new packets to process. When a packet 
 *        is ready, the worker thread will call search_packet() to scan the packet for 
 *        matches in the Aho-Corasick trie.
 *        
 * @param arg Contains the worker id which can be used to pin that worker to a specific core 
 *            and also to get that worker's buffer. 
 */
void worker_thread(void *arg) { 

    int worker_id = *(int*)arg;
    // core 0 = sniffer, 1 = stats, 2+ = workers 
    pin_thread_to_core(worker_id + 2); 
    free(arg); 

    worker_queue_t *q = &worker_queues[worker_id]; 

    while(keep_running) { 

        pthread_mutex_lock(&q->lock); 
        
        while(q->head == q->tail && keep_running) { 
            pthread_cond_wait(&q->cond, &q->lock); 
        }

        if(!keep_running) { 
            pthread_mutex_unlock(&q->lock); 
            break; 
        }

        packet_t *packet = &q->buffer[q->tail]; 
        /* 
        No longer need the 'ready' atomic flag because only one 
        specified worker can hold this lock and the sniffer only updates
        q->head after it finishes copying the data. This packet is 
        guaranteed to be ready. 
        */
        flow_entry_t *my_flow = find_or_create_flow(packet); 
        search_packet(packet, my_flow); 
        atomic_fetch_add(&engine_metrics.worker_pps[worker_id], 1); 
        q->tail = (q->tail + 1) % RING_SIZE; 
        pthread_mutex_unlock(&q->lock); 
    } 
}


/** 
 * @brief Scans the given packet data for matches in the Aho-Corasick trie. 
 *        This function is called by worker threads when they find a packet 
 *        in the ring buffer that is ready for processing. 
 *        
 *        *At the moment, this function only counts the number of matches found 
 *        using atomic variables to update the global match count, but it should 
 *        be modified to include some kind of 'reporting path'.*
 * 
 * @param packet_info Packet information to be searched for matches in the Aho-Corasick trie.
 */
void search_packet(packet_t *packet_info, flow_entry_t *flow) { 

    int current_state = flow->last_state; 
    atomic_fetch_add(&engine_metrics.acc_bytes, packet_info->length);
    atomic_fetch_add(&engine_metrics.acc_packets, 1);

    for(u_int32_t i = 0; i < packet_info->length; i++) { 
        unsigned char byte = packet_info->data[i]; 

        // while there is no transition for this byte and we're not at root, follow failure links 
        while(trie[current_state].next_state[byte] == -1 && current_state != 0) { 
            current_state = trie[current_state].failure_link;
        }

        // if there is a transition for this byte, take it
        if(trie[current_state].next_state[byte] != -1) { 
            current_state = trie[current_state].next_state[byte];
        }

        // follow dictionary links to find all matches 
        int temp_state = current_state; 
        while(temp_state != 0) { 
            if(trie[temp_state].output != -1) { 
                // printf("[!] Found pattern ID %d in packet from %s\n", trie[temp_state].output, inet_ntoa(packet_info->src_ip));
                atomic_fetch_add(&engine_metrics.acc_matches, 1); 

                // string for alert 
                char msg[ALERT_MSG_LEN]; 
                snprintf(msg, sizeof(msg), "MATCH: Pattern ID %d from %s", trie[temp_state].output, inet_ntoa(packet_info->src_ip)); 
                add_alert(1, msg); 
            }
            temp_state = trie[temp_state].dict_link; // follow dict link to find next match
        }
    }
    flow->last_state = current_state; 
}












/** 
 * @brief Inserts a pattern into the Aho-Corasick trie. Note that inserted patterns are 
 *        strings but each node of the trie is just a one byte character transition. So 
 *        for example, if we insert 'abc' with pattern ID 1, we will create a path in the 
 *        trie that goes from the root (state NULL) to byte 'a' to byte 'b' to byte 'c', and 
 *        then set the output of the final state to 1 to indicate that this path corresponds 
 *        to a pattern match with ID 1.
 * 
 * @param pattern The pattern string to be inserted.
 * @param pattern_id An integer ID associated with the pattern, used for reporting matches.
 */
void insert_pattern(const char* pattern, int pattern_id) {
    int current_state = 0; // start at root 
    for(int i = 0; pattern[i] != '\0'; i++) { 
        unsigned char byte = pattern[i]; 
        if(trie[current_state].next_state[byte] == -1) { 

            if(state_count >= MAX_STATES) { 
                fprintf(stderr, "Error: Maximum state limit reached. Cannot insert more states.\n");
                exit(1);
            }

            // create a new state if dne 
            for(int j = 0; j < ALPHABET_SIZE; j++) {
                trie[state_count].next_state[j] = -1; // initialize new state
            }
            trie[state_count].output = -1; // needs to be -1 until we set it to a pattern ID
            trie[current_state].next_state[byte] = state_count++; 
        }
        current_state = trie[current_state].next_state[byte];
    }
    trie[current_state].output = pattern_id; // marks as a match
}


/** 
 * @brief Builds the failure links for the Aho-Corasick trie.
 */

void build_failure_links() {
    int queue[MAX_STATES]; 
    int head = 0, tail = 0; 

    // set failure links for states connected to root directly
    for(int i = 0; i < ALPHABET_SIZE; i++) { 
        if(trie[0].next_state[i] != -1) { 
            trie[trie[0].next_state[i]].failure_link = 0; 
            trie[trie[0].next_state[i]].dict_link = 0; 
            queue[tail++] = trie[0].next_state[i];
        } else { 
            trie[0].next_state[i] = 0; // set missing transitions to root
        }
    }

    // bfs for remaining levels  
    while(head < tail) { 
        int r = queue[head++]; 

        for(int i = 0; i < ALPHABET_SIZE; i++) { 
            int u = trie[r].next_state[i];
            // if there is a transition from r on byte i
            if(u != -1 && u != 0) { 
                int f = trie[r].failure_link; 
                while(trie[f].next_state[i] == -1) { 
                    f = trie[f].failure_link; 
                }
                trie[u].failure_link = trie[f].next_state[i];

                /* If failure link is a match, then the dict_link is the failure link 
                If not, the dict_link of u is the same as the dict_link of its failure link */
                if(trie[trie[u].failure_link].output != -1) { 
                    trie[u].dict_link = trie[u].failure_link; 
                } else { 
                    trie[u].dict_link = trie[trie[u].failure_link].dict_link; 
                }
                queue[tail++] = u;
            }
        }
    }
} 



/** 
 * @brief Opens a .txt file containing patterns ordered one per line and 
 *        inserts them into the Aho-Corasick trie. 
 * 
 * @param filename The path to the file containing patterns to be loaded.
 */

void load_patterns(const char *filename) { 
    FILE *file = fopen(filename, "r");
    if(!file) { 
        perror("Error opening pattern file");
        exit(1); 
    }

    char line[256]; 
    int id = 1; 
    while(fgets(line, sizeof(line), file)) { 
        // remove newline character
        line[strcspn(line, "\r\n")] = 0;

        if(strlen(line) > 0) { 
            printf("Loading pattern: %s with ID %d\n", line, id);
            insert_pattern(line, id++); 
        }
    }
    fclose(file); 
    build_failure_links(); 
}




/** 
 * @brief Thread function for monitoring and printing stats about the 
 *        DPI engine's performance. 
 * 
 * @param arg Contains the CPU core number/id that will be used to pin 
 *            the stats thread using function pin_thread_to_core().
 */

void* stats_thread(void *arg) { 
    int core_id = *(int*)arg; 
    pin_thread_to_core(core_id);
    free(arg); 

    printf("\n[DPI ENGINE] Monitoring stats... \n"); 
    while(keep_running) { 
        sleep(1); 
        long b_sec = atomic_exchange(&engine_metrics.acc_bytes, 0);
        long p_sec = atomic_exchange(&engine_metrics.acc_packets, 0);
        long m_sec = atomic_exchange(&engine_metrics.acc_matches, 0);    
        long d_sec = atomic_exchange(&engine_metrics.acc_drops, 0);

        atomic_fetch_add(&engine_metrics.lifetime_bytes, b_sec); 
        atomic_fetch_add(&engine_metrics.lifetime_packets, p_sec); 
        atomic_fetch_add(&engine_metrics.lifetime_matches, m_sec); 
        atomic_fetch_add(&engine_metrics.lifetime_drops, d_sec);

        double mbps = (b_sec / 1024.0 / 1024.0) * 8; // convert bytes/s to Mbps
        atomic_store(&engine_metrics.current_mbps, mbps); 
        atomic_store(&engine_metrics.current_pps, p_sec); 

        // in the case we reach the max flow capacity quickly, the flows need to be cleared out quickly 
        // hence boundary timeout for the flow is reduced so more can be deleted. 
        if(atomic_load(&engine_metrics.active_flows) >= (engine_metrics.max_flow_capacity * 0.9)) { 
            cleanup_aged_flows(30);  
        } else { 
            cleanup_aged_flows(60); 
        }
    }
    return NULL; 
}










/** 
 * @brief This hash function uses a combination of standard hashing methods 
 *        from networking (in part 1) and Thomas Wang's hashing method. The goal 
 *        is for hashing to be fast with decent distribution rather than collision 
 *        resistant or cryptographic. If interested in space and time conscious 
 *        hashing methods, have a look at my Custom-Hashing repo at https://github.com/PD45-46 
 *          
 * @param key 5-Tuple flow key that contains packet information 
 * @return hash value to use when inputing element into hash table 
 */
uint32_t hash_5tuple(flow_key_t *key) { 

    /* 
    Combining elements of the 5-tuple to create a hash value to be 
    use later in Thomas Wang's hashing method. 
    */ 
    uint32_t hash = key->src_ip ^ key->dst_ip; 
    hash ^= (key->src_port << 16) | key->dst_port; 
    hash ^= key->protocol; 

    hash = ((hash >> 16) ^ hash) * 0x45d9f3b;
    hash = ((hash >> 16) ^ hash) * 0x45d9f3b;
    hash = (hash >> 16) ^ hash;
    return hash % FLOW_TABLE_SIZE;
}







/** 
 * @brief Tries to extract a a flow_entry_t pointer in the flow hash table. 
 *        Note that the hash table uses chaining collision hence after inputing hash 
 *        value in flow_table, we must iterate through the entry linked list. If
 *        the entry is not found, then a new flow table entry is created and placed 
 *        using the packet hash previously generated by packet_handler(). 
 * 
 * @param packet Packet to find in flow table 
 * @return Returns the entry associated with the given packet or creates a new one 
 *         using that packet's hash and returns that. 
 */
flow_entry_t* find_or_create_flow(packet_t *packet) { 
    uint32_t index = packet->hash; 

    pthread_mutex_lock(GET_FLOW_LOCK(index)); 

    flow_entry_t *entry = flow_table[index]; 
    while(entry != NULL) { 
        if(memcmp(&entry->key, &packet->key, sizeof(flow_key_t)) == 0) { 
            entry->last_seen = time(NULL); 
            pthread_mutex_unlock(GET_FLOW_LOCK(index)); 
            return entry; 
        }
        entry = entry->next; 
    }

    // create new flow if not found 
    /*
    Note: As the number of active_flows increases, if multiple workers find
    new flows at the same time, they will fight for the heap lock which slows 
    the engine down. Eventually, I can pre-allocate a pool of flow entries and 
    just grab one from the pool. 
    */
    flow_entry_t *new_flow = calloc(1, sizeof(flow_entry_t)); 
    new_flow->key = packet->key; 
    new_flow->last_state = 0; 
    new_flow->last_seen = time(NULL); 
    new_flow->next = flow_table[index]; 
    flow_table[index] = new_flow; 

    atomic_fetch_add(&engine_metrics.active_flows, 1); 

    pthread_mutex_unlock(GET_FLOW_LOCK(index)); 
    return new_flow; 
}



/** 
 * @brief 
 * @param timeout_seconds Defines how long a flow can be 'silent' until it must be removed 
 */
void cleanup_aged_flows(unsigned int timeout_seconds) { 

    time_t now = time(NULL); 

    for(int i = 0; i < FLOW_TABLE_SIZE; i++) { 

        pthread_mutex_lock(GET_FLOW_LOCK(i)); 
        flow_entry_t **curr = &flow_table[i]; 

        while(*curr) { 
            if(now - (*curr)->last_seen > timeout_seconds) { 
                flow_entry_t *to_remove = *curr; 
                *curr = to_remove->next; 
                free(to_remove); 
                atomic_fetch_sub(&engine_metrics.active_flows, 1); 
            } else { 
                curr = &((*curr)->next); 
            }
        }
        pthread_mutex_unlock(GET_FLOW_LOCK(i)); 
    }
}





/** 
 * @brief Handler for interrupt signal 
 * @param sig Any signal will lead to termination (for now...)
 */
void signal_handler(int sig) { 
    (void)sig; 
    keep_running = false; 
    if(handle) pcap_breakloop(handle); 
    printf("Exit Program\n");  
}





/* MAIN */
int main(int argc, char *argv[]) { 
    signal(SIGINT, signal_handler); 

    char *dev = NULL; 
    char errbuf[PCAP_ERRBUF_SIZE]; 
    char *pattern_file = NULL; 

    // device lookup
    if(argc > 1) { 
        dev = argv[1]; 
        pattern_file = argv[2];
    } else { 
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
            return 1;
        }
        dev = strdup(alldevs->name); // Take the first device
        pcap_freealldevs(alldevs);
    }

    // heap alloc 
    worker_queues = calloc(NUM_WORKERS, sizeof(worker_queue_t));
    worker_threads = malloc(NUM_WORKERS * sizeof(pthread_t));
    
    if(!worker_queues || !worker_threads) {
        fprintf(stderr, "Failed to allocate memory for workers\n");
        return 1;
    }

    // init queue locks (before threads)
    for(int i = 0; i < NUM_WORKERS; i++) {
        worker_queues[i].head = 0; 
        worker_queues[i].tail = 0;
        pthread_mutex_init(&worker_queues[i].lock, NULL); 
        pthread_cond_init(&worker_queues[i].cond, NULL); 
    }

    for(int i = 0; i < NUM_FLOW_LOCKS; i++) { 
        pthread_mutex_init(&flow_locks[i], NULL); 
    }

    
    /* 
    trie set up 
    Note that since we only have one Aho-Corasick model to use, we don't 
    NEED to have the trie on the heap, in this case its ok to just leave
    it on the stack. 
    */
    for(int i = 0; i < ALPHABET_SIZE; i++) {
        trie[0].next_state[i] = -1;
    }
    trie[0].output = -1;
    state_count = 1;

    if(pattern_file == NULL) { 
        fprintf(stderr, "Failed to init pattern file\n"); 
        return 1; 
    }

    load_patterns(pattern_file);

    // worker thread init 
    for(int i = 0; i < NUM_WORKERS; i++) {
        int *worker_id_arg = malloc(sizeof(int));
        *worker_id_arg = i; 
        
        if(pthread_create(&worker_threads[i], NULL, (void*)worker_thread, worker_id_arg) != 0) { 
            fprintf(stderr, "Error creating worker thread %d\n", i);
            return 1;
        } 
    }

    // stats monitor 
    pthread_t monitor_id; 
    int *stats_arg = malloc(sizeof(int));
    *stats_arg = NUM_WORKERS + 2;
    pthread_create(&monitor_id, NULL, (void*)stats_thread, stats_arg);

    // sniffer setup
    handle = pcap_create(dev, errbuf);
    pcap_set_snaplen(handle, MAX_PACKET_SIZE); 
    pcap_set_promisc(handle, 1); 
    pcap_set_timeout(handle, 0);
    pcap_set_immediate_mode(handle, 1); 
    pcap_set_buffer_size(handle, 512 * 1024 * 1024); 
    pcap_activate(handle); 

    pin_thread_to_core(1); 

    start_ui_thread(); 

    printf("Sniffing on device: %s\n", dev); 
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}