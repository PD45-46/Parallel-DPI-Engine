#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "../include/protocol_headers.h"
#include <pthread.h>
#include "../include/aho_corasick.h"
#include <string.h>


#define RING_SIZE 1024
#define MAX_STATES 1000 // note that states are chars in trie, not patterns 

packet_t ring_buffer[RING_SIZE]; 
int ring_head = 0;
int ring_tail = 0;

pthread_mutex_t buffer_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t data_ready = PTHREAD_COND_INITIALIZER;

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_payload(const u_char *payload, int len);
void worker_thread(void *arg);

void search_packet(packet_t *packet_info); 

void insert_pattern(const char* pattern, int pattern_id); 
/** 
 * @brief This function is called every time a packet is captured. 
 */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    const sniff_ip *ip_header;
    const sniff_tcp *tcp_header;
    const char *payload;

    // Use hardcoded offsets for speed
    ip_header = (sniff_ip*)(packet + sizeof(sniff_ethernet));
    int size_ip = IP_HL(ip_header) * 4;

    if (size_ip < 20) return;

    if (ip_header->ip_p == IPPROTO_TCP) {

        int payload_len = ntohs(ip_header->ip_len) - (size_ip + (TH_OFF((sniff_tcp*)(packet + sizeof(sniff_ethernet) + size_ip)) * 4));
        pthread_mutex_lock(&buffer_lock);

        int next_head = (ring_head + 1) % RING_SIZE;
        if(next_head != ring_tail) { 
            packet_t *packet_info = &ring_buffer[ring_head];
            packet_info->length = ntohs(ip_header->ip_len);
            packet_info->src_ip = ip_header->ip_src;

            memcpy(packet_info->data, packet + sizeof(sniff_ethernet) + size_ip + (TH_OFF((sniff_tcp*)(packet + sizeof(sniff_ethernet) + size_ip)) * 4), payload_len);
        
            ring_head = next_head;
            pthread_cond_signal(&data_ready);
        } else {
            printf("Ring buffer full, dropping packet\n");
            // TODO: Implement a better strategy for handling buffer overflow (e.g., overwrite oldest, log, etc.)
        
        }
        pthread_mutex_unlock(&buffer_lock);
    }
    /* 
    packet is ptr to raw bytes. 
    Byte 0 - 13: Ethernet header
    Byte 14 - 33: IP header (if Ethernet type is IPv4)
    Byte 34 - 53: TCP header (if IP protocol is TCP)
    */
}

void print_payload(const u_char *payload, int len) {
    const u_char *ch = payload;
    printf("   ");
    for(int i = 0; i < len; i++) {
        if (isprint(*ch)) // If it's a readable character (A, B, 1, @)
            printf("%c", *ch);
        else
            printf("."); // If it's binary data
        ch++;
    }
    printf("\n");
}












void worker_thread(void *arg) { 
    while(1) { 
        pthread_mutex_lock(&buffer_lock);
        while (ring_head == ring_tail) {
            pthread_cond_wait(&data_ready, &buffer_lock);
        }

        packet_t packet_info = ring_buffer[ring_tail];
        ring_tail = (ring_tail + 1) % RING_SIZE;
        pthread_mutex_unlock(&buffer_lock);

        // Process packet_info (e.g., print, analyze, etc.)
        // printf("Worker thread processing packet from %s with length %d\n", inet_ntoa(packet_info.src_ip), packet_info.length);
        search_packet(&packet_info);
    }
}



void search_packet(packet_t *packet_info) { 
    int current_state = 0; 
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
                printf("[!] Found pattern ID %d in packet from %s\n", trie[temp_state].output, inet_ntoa(packet_info->src_ip));
            }
            temp_state = trie[temp_state].dict_link; // follow dict link to find next match
        }
    }
}












/** 
 * @brief Inserts a pattern into the Aho-Corasick trie. 
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
 * 
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





int main(int argc, char *argv[]) { 
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle; 
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

    // open device for live capture (sniffing)
    // 65535 is the maximum packet size to capture (SNAPLEN)
    handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);

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
    pthread_t worker_id; 
    if(pthread_create(&worker_id, NULL, (void*)worker_thread, NULL) != 0) { 
        fprintf(stderr, "Error creating worker thread\n");
        return 1;
    } 


    // start the capture loop
    printf("Sniffing on device: %s\n", dev); 
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}