#ifndef PROTOCOL_HEADERS_H
#define PROTOCOL_HEADERS_H

#include <arpa/inet.h>
#include <stdbool.h> 
#include <stdatomic.h>
#include "flow_table.h"

#define RING_SIZE 1024 // 2^10 -> allows for bitwise 
#define MAX_PACKET_SIZE 1800 // must pay respect to CONF_FRAME_SIZE in ingress.h 
#define NUM_WORKERS 4
#define GLOBAL_PPS_LIMIT 10000 // a worker can only process 10,000 packets per second at max

// Ethernet header (always 14 bytes)
typedef struct { 
    u_char ether_dhost[6]; // destination host address
    u_char ether_shost[6]; // source host address
    u_short ether_type;    // IP, ARP, RARP, etc.
} sniff_ethernet;

// IP Header ()
typedef struct { 
    u_char ip_vhl;                 // version << 4 | header length >> 2
    u_char ip_tos;                 // type of service
    u_short ip_len;                 // total length
    u_short ip_id;                  // identification field
    u_short ip_off;                 // fragment offset field
    u_char ip_ttl;                 // time to live
    u_char ip_p;                   // protocol (TCP, UDP, etc.)
    u_short ip_sum;                 // checksum  
    struct in_addr ip_src, ip_dst; // source and dest address
} sniff_ip; 
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f) // IP header length in 32-bit words

// TCP header (variable length, minimum 20 bytes)
typedef struct { 
    u_short th_sport;     // source port
    u_short th_dport;     // destination port
    u_int32_t th_seq;     // sequence number 
    u_int32_t th_ack;     // acknowledgment number 
    u_char th_offx2;      // data offset, rsvd
    u_char th_flags;      // TCP flags 
    u_short th_win;       // window
    u_short th_sum;       // checksum
    u_short th_urp;       // urgent pointer
} sniff_tcp;
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4) // TCP header length in 32-bit words

// shared packet structure for threading 

typedef struct { 
    u_char data[MAX_PACKET_SIZE];
    u_int32_t length; 
    struct in_addr src_ip;
    u_short src_port; 
    atomic_bool ready; 
    flow_key_t key; 
    uint32_t hash; 
} packet_t; 


typedef struct { 
    packet_t buffer[RING_SIZE]; 
    int head; 
    int tail; 
    pthread_mutex_t lock; 
    pthread_cond_t cond; 
} worker_queue_t; 

extern worker_queue_t *worker_queues; 

#endif