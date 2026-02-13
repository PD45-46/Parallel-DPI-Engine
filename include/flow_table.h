#ifndef FLOW_TABLE
#define FLOW_TABLE 

#include <stdint.h> 
#include <pthread.h> 

#define FLOW_TABLE_SIZE 65536 // 2^16 buckets 
#define FLOW_HASH_MASK (FLOW_TABLE_SIZE - 1)
#define NUM_FLOW_LOCKS 1024 
#define GET_FLOW_LOCK(hash) &flow_locks[(hash) % NUM_FLOW_LOCKS] 


/*
Notice that with this implementation, if the key word is 'MATCH' and packets 
arrive in the order 'TCH' then 'MA', the Ah-Corasick algorithm will miss the 
case due to the nature of how the algorithm operates. 
*/

// 5-tuple flow table 
typedef struct { 
    uint32_t src_ip;
    uint32_t dst_ip; 
    uint16_t src_port; 
    uint16_t dst_port; 
    uint8_t protocol; 
} flow_key_t; 

typedef struct flow_entry { 
    flow_key_t key; 
    int last_state;              // Aho-Corasick trie state where we left off
    uint64_t last_seen;          // timestamp for aging out of old flows 
    struct flow_entry *next;     // for handling hash collisions using regular chaining method
} flow_entry_t; 

flow_entry_t *flow_table[FLOW_TABLE_SIZE]; 
pthread_mutex_t flow_locks[NUM_FLOW_LOCKS]; 

#endif