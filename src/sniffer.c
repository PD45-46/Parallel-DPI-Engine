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
#include "../include/ingress.h"
#include "../include/l7_protocol.h"
#include <poll.h> 
#include <string.h>
#include <stdatomic.h> 
#include <signal.h> 
#include <stdarg.h>


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
    .max_flow_capacity = MAX_TOTAL_FLOWS, 

    .http_count = ATOMIC_VAR_INIT(0), 
    .tls_count = ATOMIC_VAR_INIT(0)
};

alert_t alert_queue[MAX_ALERTS]; 
int alert_head = 0; 
int alert_tail = 0; 
pthread_mutex_t alert_lock = PTHREAD_MUTEX_INITIALIZER; 



// globals defined in aho-corasick.h

ACNode trie[MAX_STATES]; 
int state_count = 1; 
int loaded_count = 0; 


// globals defined in flow_table.h

flow_entry_t *flow_table[FLOW_TABLE_SIZE]; 
pthread_mutex_t flow_locks[NUM_FLOW_LOCKS]; 
flow_entry_t flow_pool[MAX_TOTAL_FLOWS]; 
int flow_free_stack[MAX_TOTAL_FLOWS]; 
int stack_ptr = MAX_TOTAL_FLOWS - 1; 
pthread_mutex_t pool_lock = PTHREAD_MUTEX_INITIALIZER; 

// globals defined in protocol_headers.h

worker_queue_t *worker_queues = NULL; 

// globals defined in this file

pthread_t *worker_threads = NULL;

static volatile bool keep_running = true; 

int offset = 14;

pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER; 



// declarations

void init_trie(); 

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_payload(const u_char *payload, int len);
void worker_thread(void *arg);
void search_packet(packet_t *packet_info, flow_entry_t *flow); 

void insert_pattern(const char* pattern, int pattern_id); 
void build_failure_links();

uint32_t hash_5tuple(flow_key_t *key); 
flow_entry_t* find_or_create_flow(packet_t *packet); 
void cleanup_aged_flows(unsigned int timeout_seconds); 

void run_sniffer_loop(af_packet_handle_t *h); 

void debug_log(const char *fmt, ...); 


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
 * @brief Initialises the trie values.
 * 
 */
void init_trie() { 
    state_count = 1; 
    for(int i = 0; i < MAX_STATES; i++) { 
        trie[i].output = -1; 
        trie[i].failure_link = 0; 
        trie[i].dict_link = 0; 
        for(int j = 0; j < ALPHABET_SIZE; j++) { 
            trie[i].next_state[j] = -1; 
        }
    }
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
 * @brief Input function for worker thread loop when calling pthread_create(). 
 *        Each worker thread will pin itself to the specified CPU core and then 
 *        continuously check the ring buffer for new packets to process. When a packet 
 *        is ready, the worker thread will call search_packet() to scan the packet for 
 *        matches in the Aho-Corasick trie.
 * 
 *        UPDATE -- 
 *          Note that initially I was copying memory from Kernel space to User space 
 *          but now I am just taking information that the Kernel stores in RAM directly. 
 *          Read ingress.h & ingress.c for more info. 
 *        
 * @param arg Contains the worker id which can be used to pin that worker to a specific core 
 *            and also to get that worker's buffer. 
 */
void worker_thread(void *arg) { 

    int worker_id = *(int*)arg;
    // core 0 = sniffer, 1 = stats, 2+ = workers 
    pin_thread_to_core(worker_id + 2); 
    free(arg); 

    af_packet_handle_t *h = setup_af_packet("lo"); // hard coded for now

    struct pollfd pfd = {  
        .fd = h->socket_fd, 
        .events = POLLIN 
    };

    struct timespec start, end; 
    struct timespec start_total, end_total; 
    double delta; 
    double old_avg_time; 
    double elapsed_time; 

    while(keep_running) { 

        clock_gettime(CLOCK_MONOTONIC, &start_total); 

        struct tpacket2_hdr *hdr = (struct tpacket2_hdr *)(h->map + (h->current_frame * h->ring_req.tp_frame_size)); 

        if(!(hdr->tp_status & TP_STATUS_USER)) {
            poll(&pfd, 1, 10);
            continue;
        }

        uint8_t *raw_packet = (uint8_t *)hdr + hdr->tp_mac;
        int link_offset = offset; 
        const sniff_ip *ip = (sniff_ip*)(raw_packet + link_offset); 

        if(ip->ip_vhl >> 4 != 4) { 
            atomic_fetch_add(&engine_metrics.acc_drops, 1); 
            goto next_frame; 
        }

        l7_proto_t protocol = identify_l7_protocol(raw_packet, hdr->tp_len); 

        
        if(protocol == PROTO_HTTP) { 
            atomic_fetch_add(&engine_metrics.http_count, 1); 
        } else if(protocol == PROTO_TLS) { 
            atomic_fetch_add(&engine_metrics.tls_count, 1); 
        }

        int size_ip = IP_HL(ip) * 4; 
        if (ip->ip_p != IPPROTO_TCP) {
            atomic_fetch_add(&engine_metrics.acc_drops, 1); 
            goto next_frame;
        }
        

        const sniff_tcp *tcp = (sniff_tcp*)(raw_packet + link_offset + size_ip);
        int size_tcp = TH_OFF(tcp) * 4;
        int payload_len = ntohs(ip->ip_len) - size_ip - size_tcp;

        // prepare packet_t for the search algorithm
        packet_t pkt_info;
        pkt_info.length = (payload_len > MAX_PACKET_SIZE) ? MAX_PACKET_SIZE : payload_len;
        pkt_info.src_ip = ip->ip_src;
        pkt_info.key = (flow_key_t){
            .src_ip = ip->ip_src.s_addr, .dst_ip = ip->ip_dst.s_addr,
            .src_port = tcp->th_sport, .dst_port = tcp->th_dport,
            .protocol = ip->ip_p
        };
        pkt_info.hash = hash_5tuple(&pkt_info.key); 
        memcpy(pkt_info.data, (uint8_t*)tcp + size_tcp, pkt_info.length);

        // process Flow and Aho-Corasick

        clock_gettime(CLOCK_MONOTONIC, &start); 
        flow_entry_t *my_flow = find_or_create_flow(&pkt_info); 
        clock_gettime(CLOCK_MONOTONIC, &end); 
        delta = (end.tv_sec - start.tv_sec) * 1e6 + (end.tv_nsec - start.tv_nsec); 
        old_avg_time = atomic_load(&engine_metrics.worker_avg_hash[worker_id]);
        elapsed_time = (delta * EMA_ALPHA) + (old_avg_time * (1.0 - EMA_ALPHA)); 
        atomic_store(&engine_metrics.worker_avg_hash[worker_id], elapsed_time);

        clock_gettime(CLOCK_MONOTONIC, &start); 
        search_packet(&pkt_info, my_flow); 
        clock_gettime(CLOCK_MONOTONIC, &end); 
        delta = (end.tv_sec - start.tv_sec) * 1e6 + (end.tv_nsec - start.tv_nsec); 
        old_avg_time = atomic_load(&engine_metrics.worker_avg_algo[worker_id]);
        elapsed_time = (delta * EMA_ALPHA) + (old_avg_time * (1.0 - EMA_ALPHA)); 
        atomic_store(&engine_metrics.worker_avg_algo[worker_id], elapsed_time);
        
        

        // return frame to Kernel
    next_frame: 
        hdr->tp_status = TP_STATUS_KERNEL;
        h->current_frame = (h->current_frame + 1) % h->ring_req.tp_frame_nr;

        clock_gettime(CLOCK_MONOTONIC, &end_total); 
        delta = (end_total.tv_sec - start_total.tv_sec) * 1e6 + (end_total.tv_nsec - start_total.tv_nsec); 
        old_avg_time = atomic_load(&engine_metrics.worker_avg_wait[worker_id]);
        elapsed_time = (delta * EMA_ALPHA) + (old_avg_time * (1.0 - EMA_ALPHA)); 
        atomic_store(&engine_metrics.worker_avg_wait[worker_id], elapsed_time);
    } 
    teardown_af_packet(h);
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
    static _Atomic int counter = 0;
    int c = atomic_fetch_add(&counter, 1);

    if(!flow) return; 

    pthread_mutex_lock(&flow->lock); 

    int current_state = flow->last_state; 
    atomic_fetch_add(&engine_metrics.acc_bytes, packet_info->length);
    atomic_fetch_add(&engine_metrics.acc_packets, 1);

    if (c % 10000 == 0) {
        debug_log("[SAMPLE] Pkt Len: %d | Data[0]: %02x | State: %d", 
                  packet_info->length, packet_info->data[0], flow->last_state);
    }

    for(u_int32_t i = 0; i < packet_info->length; i++) { 
        unsigned char byte = packet_info->data[i]; 
        

        // while there is no transition for this byte and we're not at root, follow failure links 
        while(trie[current_state].next_state[byte] == -1 && current_state != 0) { 
            current_state = trie[current_state].failure_link;
        }

        int next = trie[current_state].next_state[byte];
        current_state = (next != -1) ? next : 0;

        // follow dictionary links to find all matches 
        int temp_state = current_state; 
        while(temp_state != 0) { 
            if(trie[temp_state].output != -1) { 
                int m = atomic_fetch_add(&engine_metrics.acc_matches, 1); 
                // debug_log("increment acc_matches: %i | search_packet()", m); 


                // string for alert 
                
                char msg[ALERT_MSG_LEN]; 
                char ip_str[INET_ADDRSTRLEN]; 
                inet_ntop(AF_INET, &packet_info->src_ip, ip_str, INET_ADDRSTRLEN);
                snprintf(msg, sizeof(msg), "MATCH: Pattern ID %d from %s", trie[temp_state].output, ip_str); 
                // debug_log("Creating alert msg: %s | search_packet()", msg); 
                add_alert(1, msg); 
            }
            temp_state = trie[temp_state].dict_link; // follow dict link to find next match
        }
    }
    flow->last_state = current_state; 
    pthread_mutex_unlock(&flow->lock); 
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
 * TODO: Change to be faster O(n * failure depth) -> O(n)
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
        debug_log("Failed to open file: %s", filename); 
        exit(1); 
    }

    char line[256]; 
    int id = 1; 

    while(fgets(line, sizeof(line), file)) { 
        // remove newline character
        line[strcspn(line, "\r\n")] = 0;

        if(strlen(line) > 0) { 
            debug_log("Loading pattern: %s with ID %d\n", line, id);
            insert_pattern(line, id++); 
            loaded_count++; 
        }
    }
    fclose(file); 
    build_failure_links(); 

    debug_log("LOADED PATTERNS -- Total Trie States: %d", loaded_count); 
    sleep(1); 
}




/** 
 * @brief Thread function for monitoring and printing stats about the 
 *        DPI engine's performance. 
 * 
 * @param arg Contains the CPU core number/id that will be used to pin 
 *            the stats thread using function pin_thread_to_core().
 * 
 * TODO - Exclude worker_queues, they're no longer used 
 */

void* stats_thread(void *arg) { 
    int core_id = *(int*)arg; 
    pin_thread_to_core(core_id);
    free(arg); 

    // printf("\n[DPI ENGINE] Monitoring stats... \n"); 
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

        for (int i = 0; i < NUM_WORKERS; i++) {
            worker_queue_t *q = &worker_queues[i];
            
            int head = q->head;
            int tail = q->tail;
            int occupied = (head - tail + RING_SIZE) % RING_SIZE;
            
            double load_percent = ((double)occupied / (RING_SIZE - 1)) * 100.0;
            atomic_store(&engine_metrics.worker_load[i], load_percent);
        }

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

    // will be creating a new flow from pre-alloc pool instead of heap 
    pthread_mutex_lock(&pool_lock); 
    if(stack_ptr < 0) { 
        pthread_mutex_unlock(&pool_lock); 
        pthread_mutex_unlock(GET_FLOW_LOCK(index)); 
        return NULL; 
    } 

    int pool_idx = flow_free_stack[stack_ptr--]; 
    pthread_mutex_unlock(&pool_lock); 

    flow_entry_t *new_flow = &flow_pool[pool_idx]; 
    memset(new_flow, 0, sizeof(flow_entry_t)); 
    new_flow->key = packet->key; 
    new_flow->last_seen = time(NULL); 
    pthread_mutex_init(&new_flow->lock, NULL); 
    
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
                int pool_idx = to_remove - flow_pool; 
                pthread_mutex_lock(&pool_lock); 
                if(stack_ptr < MAX_TOTAL_FLOWS - 1) { 
                    flow_free_stack[++stack_ptr] = pool_idx; 
                }
                pthread_mutex_unlock(&pool_lock); 
                atomic_fetch_sub(&engine_metrics.active_flows, 1); 
            } else { 
                curr = &((*curr)->next); 
            }
        }
        pthread_mutex_unlock(GET_FLOW_LOCK(i)); 
    }
}





void debug_log(const char *fmt, ...) { 
    pthread_mutex_lock(&log_lock);
    FILE *f = fopen("engine_debug.log", "a"); 
    if(f) { 
        va_list args; 
        va_start(args, fmt); 
        vfprintf(f, fmt, args);
        va_end(args);
        fprintf(f, "\n");

        fflush(f); 
        fsync(fileno(f));

        fclose(f);
    }
    pthread_mutex_unlock(&log_lock); 
}









/** 
 * @brief Handler for interrupt signal 
 * @param sig Any signal will lead to termination (for now...)
 * 
 * TODO - Change signals... 
 */
void signal_handler(int sig) { 
    (void)sig; 
    keep_running = false; 
    // if(handle) pcap_breakloop(handle); 
    printf("Exit Program\n");  
}





/* MAIN */
int main(int argc, char *argv[]) { 

    signal(SIGINT, signal_handler); 
    init_trie(); 
    debug_log("START LOG"); 
    // char *dev = (argc > 1) ? argv[1] : "eth0"; 
    char *pattern_file = (argc > 2) ? argv[2] : NULL; 


    load_patterns(pattern_file); 
    debug_log("DEBUG: Trie loaded with %d states", state_count); 
    if(state_count > 0) { 
        debug_log("DEBUG: Transition for 'M' (0x4d) from root %d", trie[0].next_state[0x4d]); 
    }


    for(int i = 0; i < NUM_FLOW_LOCKS; i++) pthread_mutex_init(&flow_locks[i], NULL);
    for(int i = 0; i < MAX_TOTAL_FLOWS; i++) { 
        flow_free_stack[i] = i; 

    }
    worker_queues = calloc(NUM_WORKERS, sizeof(worker_queue_t));
    worker_threads = malloc(NUM_WORKERS * sizeof(pthread_t));    
    for(int i = 0; i < NUM_WORKERS; i++) {
        int *worker_id_arg = malloc(sizeof(int));
        *worker_id_arg = i; 
        pthread_create(&worker_threads[i], NULL, (void*)worker_thread, worker_id_arg);
    }

    pthread_t monitor_id;
    int *stats_arg = malloc(sizeof(int)); *stats_arg = NUM_WORKERS + 2;
    pthread_create(&monitor_id, NULL, (void*)stats_thread, stats_arg);

    start_ui_thread(); 
    while(keep_running) { sleep(1); }

    for(int i = 0; i < NUM_WORKERS; i++) { 
        pthread_join(worker_threads[i], NULL); 
    }
    pthread_join(monitor_id, NULL); 
    free(worker_threads); 

    return 0;
}