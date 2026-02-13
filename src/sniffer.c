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
#include <string.h>
#include <stdatomic.h> 
#include <signal.h> 


#define RING_SIZE 131072 // 2^17 -> allows for bitwise 
#define NUM_WORKERS 4 

pthread_t worker_threads[NUM_WORKERS];

packet_t *ring_buffer; 
int ring_head = 0;
int ring_tail = 0;

pthread_mutex_t buffer_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t data_ready = PTHREAD_COND_INITIALIZER;

atomic_long total_bytes_scanned = 0; 
atomic_long total_packets_processed = 0;
atomic_long total_matches_found = 0; 
atomic_long total_packets_dropped = 0; 
atomic_long lifetime_matches = 0; 
atomic_long lifetime_packets = 0; 

volatile bool keep_running = true; 

pcap_t *handle = NULL; 


void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_payload(const u_char *payload, int len);
void worker_thread(void *arg);
void search_packet(packet_t *packet_info, flow_entry_t *flow); 

void insert_pattern(const char* pattern, int pattern_id); 
void build_failure_links();

uint32_t hash_5tuple(flow_key_t *key); 
flow_entry_t* find_or_create_flow(packet_t *packet); 



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
 * @param args User defined arguments (not used in this case, set to NULL when calling pcap_loop())
 * @param header Metadata about the captured packet (timestamp, length, etc.)
 * @param packet Pointer to the raw packet data captured by pcap. This includes the Ethernet header, 
 *               IP header, TCP header, and payload. 
 */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    const sniff_ethernet *eth = (sniff_ethernet*)(packet); 
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
    
    // reserve index in ring buffer to reduce lock holding time 
    pthread_mutex_lock(&buffer_lock);
    int next_head = (ring_head + 1) % RING_SIZE;
    if(next_head == ring_tail) { 
        pthread_mutex_unlock(&buffer_lock);
        atomic_fetch_add(&total_packets_dropped, 1);
        return; // buffer is full, drop packet (TODO: implement better strategy for handling this)
    }
    int reserved_index = ring_head; 
    ring_head = next_head; 
    pthread_mutex_unlock(&buffer_lock);

    packet_t *packet_info = &ring_buffer[reserved_index]; 
    packet_info->ready = false; // mark as not ready until fully populated
    packet_info->length = payload_len; 
    packet_info->src_ip = ip_header->ip_src;

    packet_info->key = key; 
    packet_info->hash = hash_5tuple(&key); 
    
    if(payload_len > 0) { 
        memcpy(packet_info->data, packet + payload_offset, 
            (payload_len > MAX_PACKET_SIZE) ? MAX_PACKET_SIZE : payload_len); 
    } else { 

    }
    packet_info->ready = true; // mark as ready for processing
    pthread_cond_signal(&data_ready); // signal one worker thread that a new packet is ready for processing
}


/**
 * @brief Used too print specific information about the given payload. 
 *        This function is archived (no longer in use). 
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
 * @param arg Contains the CPU core number/id that will be used to pin 
 *            the worker thread using function pin_thread_to_core(). 
 */
void worker_thread(void *arg) { 

    int core_id = *(int*)arg;
    pin_thread_to_core(core_id); 
    free(arg); 

    while(keep_running) { 
        int index_to_process = -1; 

        pthread_mutex_lock(&buffer_lock);
        if(ring_head != ring_tail) { 
            index_to_process = ring_tail;
            ring_tail = (ring_tail + 1) % RING_SIZE;
        }
        pthread_mutex_unlock(&buffer_lock);

        if(index_to_process != -1) { 
            while(!atomic_load(&ring_buffer[index_to_process].ready)) { 
                __builtin_ia32_pause(); // hint to CPU that we're in spin wait
            }
            flow_entry_t *my_flow = find_or_create_flow(&ring_buffer[index_to_process]); 
            search_packet(&ring_buffer[index_to_process], my_flow);
            atomic_store(&ring_buffer[index_to_process].ready, false);
        } else { 
            usleep(5); 
        }
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
    atomic_fetch_add(&total_bytes_scanned, packet_info->length);
    atomic_fetch_add(&total_packets_processed, 1);

    for(int i = 0; i < packet_info->length; i++) { 
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
                atomic_fetch_add(&total_matches_found, 1);
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
    for(int i = 0; i < pattern[i] != '\0'; i++) { 
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
 * @param arg Contains the CPU core number/id that will be used to pin 
 *            the stats thread using function pin_thread_to_core().
 */

void* stats_thread(void *arg) { 
    int core_id = *(int*)arg; 
    pin_thread_to_core(core_id);
    free(arg); 

    printf("\n[DPI ENGINE] Monitoring stats... \n"); 
    while(keep_running) { 
        sleep(3); 
        long bytes = atomic_exchange(&total_bytes_scanned, 0);
        long packets = atomic_exchange(&total_packets_processed, 0);
        long matches = atomic_exchange(&total_matches_found, 0);    
        long rb_drops = atomic_exchange(&total_packets_dropped, 0);

        atomic_fetch_add(&lifetime_packets, packets); 
        atomic_fetch_add(&lifetime_matches, matches); 

        long std_lifetime_packets = atomic_load(&lifetime_packets); 
        long std_lifetime_matches = atomic_load(&lifetime_matches);
        
        double hit_rate = 0.0;  
        if(std_lifetime_packets > 0) { 
            hit_rate = ((double)std_lifetime_matches / (double)std_lifetime_packets) * 100.0;
        }

        

        double mbps = (bytes / 1024.0 / 1024.0) * 8; // convert bytes/s to Mbps

        printf("\r\033[K[STATS] %.2f MB/s | PPS: %ld | M: %ld | Drp: %ld | Total Pkt: %ld | Total M: %ld | Hit: %.2f%%", 
            mbps, packets, matches, rb_drops, std_lifetime_packets, std_lifetime_matches, hit_rate);
        fflush(stdout); 


        // flow aging -> to avoid mem to fill up with dead connections 
        // we do this in stats thread because it only activates every few seconds 
        time_t now = time(NULL); 
        for(int i = 0; i < FLOW_TABLE_SIZE; i++) { 
            pthread_mutex_lock(GET_FLOW_LOCK(i)); 
            flow_entry_t **curr = &flow_table[i]; 

            while(*curr) { 
                if(now - (*curr)->last_seen > 60) { 
                    flow_entry_t *to_remove = *curr; 
                    *curr = to_remove->next; 
                    free(to_remove); 
                } else { 
                    curr = &((*curr)->next); 
                }
            }
            pthread_mutex_unlock(GET_FLOW_LOCK(i)); 
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
 * @brief
 * @param packet
 * @return 
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
    flow_entry_t *new_flow = calloc(1, sizeof(flow_entry_t)); 
    new_flow->key = packet->key; 
    new_flow->last_state = 0; 
    new_flow->last_seen = time(NULL); 
    new_flow->next = flow_table[index]; 
    flow_table[index] = new_flow; 

    pthread_mutex_unlock(GET_FLOW_LOCK(index)); 
    return new_flow; 
}






void signal_handler(int sig) { 
    keep_running = false; 
    if(handle) pcap_breakloop(handle); 
    printf("Exit Program\n");  
}






/** MAIN... */
int main(int argc, char *argv[]) { 

    signal(SIGINT, signal_handler); 

    ring_buffer = calloc(RING_SIZE, sizeof(packet_t)); // zeros out the ring buffer and sets all packet_t.ready to false
    if(ring_buffer == NULL) { 
        fprintf(stderr, "Failed allocating ring buffer\n");
        return 1; 
    }

    pin_thread_to_core(1); // pin main thread (sniffer) to core 1 (note: core 0 reserved for flooding traffic)


    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE]; 
    char *pattern_file; 

    if(argc > 1) { 
        // use lo for local testing, otherwise find a default device -> internet 
        dev = argv[1]; 
        pattern_file = argv[2];
    } else { 
        // find a default device to capture from
        dev = pcap_lookupdev(errbuf);
        if(dev == NULL) { 
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            return 1;
        }
    }

    // create pcap buffer instead of 
    handle = pcap_create(dev, errbuf);
    pcap_set_snaplen(handle, MAX_PACKET_SIZE); 
    pcap_set_promisc(handle, 1); 
    pcap_set_timeout(handle, 0);
    pcap_set_immediate_mode(handle, 1); // get packets to worker threads as soon as they arrive, rather than buffering in kernel  
    pcap_set_buffer_size(handle, 512 * 1024 * 1024); // 512 MB buffer for pcap (smaller the buffer, faster the kernal buffer fills up with packets) 
    pcap_activate(handle); 

    // init trie root 
    for(int i = 0; i < ALPHABET_SIZE; i++) {
        trie[0].next_state[i] = -1; // initialize root state
    }
    trie[0].output = -1; // no pattern ends at root
    state_count = 1;

    load_patterns(pattern_file);

    /* TODO: ONLY ONE WORKER THREAD ACTIVE AT A TIME. */
    /* NOTE: 
       We have two sections of the program, first being the packet sniffer (main thread) and 
       second being the worker thread that processes packets from the ring buffer. Keep in mind 
       that pthread_create only creates one thread that will run the worker_thread function to 
       process packets. Adding more worker threads will add more 'computing speed' to only processing 
       but not information gathering. This means that we will be limited by the speed of the packet sniffer. 
    */
    
    for(int i = 0; i < NUM_FLOW_LOCKS; i++) { 
        pthread_mutex_init(&flow_locks[i], NULL); 
    }
    
    for(int i = 0; i < NUM_WORKERS; i++) {
        int *core_arg = malloc(sizeof(int));
        *core_arg = i + 2; 
        if(pthread_create(&worker_threads[i], NULL, (void*)worker_thread, core_arg) != 0) { 
            fprintf(stderr, "Error creating worker thread %d\n", i);
            return 1;
        } 
        
    }

    pthread_t monitor_id; 
    int *stats_arg = malloc(sizeof(int));
    *stats_arg = NUM_WORKERS + 2;
    if(pthread_create(&monitor_id, NULL, (void*)stats_thread, stats_arg) != 0) { 
        fprintf(stderr, "Error creating stats thread\n");
        return 1;
    }


    // start the capture loop
    printf("Sniffing on device: %s\n", dev); 
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}