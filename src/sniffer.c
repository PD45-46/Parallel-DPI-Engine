#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "../include/protocol_headers.h"
#include <pthread.h>

#define RING_SIZE 1024

packet_t ring_buffer[RING_SIZE]; 
int ring_head = 0;
int ring_tail = 0;

pthread_mutex_t buffer_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t data_ready = PTHREAD_COND_INITIALIZER;

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_payload(const u_char *payload, int len);
void worker_thread(void *arg);

/** 
 * @brief This function is called every time a packet is captured. 
 */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    const sniff_ip *ip_header;
    const sniff_tcp *tcp_header;
    const char *payload;

    // Use hardcoded offsets for speed (HFT Style)
    ip_header = (sniff_ip*)(packet + sizeof(sniff_ethernet));
    int size_ip = IP_HL(ip_header) * 4;

    if (size_ip < 20) return;

    if (ip_header->ip_p == IPPROTO_TCP) {

        int payload_len = ntohs(ip_header->ip_len) - (size_ip + (TH_OFF((sniff_tcp*)(packet + sizeof(sniff_ethernet) + size_ip)) * 4));
        pthread_mutex_lock(&buffer_lock);

        int next_head = (ring_head + 1) % RING_SIZE;
        if(next_head != ring_tail) { 
            packet_t *packet_info = &ring_buffer[ring_head];
            packet_info->length = ip_header->ip_len;
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
        printf("Worker thread processing packet from %s with length %d\n", inet_ntoa(packet_info.src_ip), packet_info.length);
    }
}

int main() { 
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle; 

    // find a default device to capture from 
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL) { 
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 1;
    }

    // open device for live capture (sniffing)
    // 65535 is the maximum packet size to capture (SNAPLEN)
    handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);


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