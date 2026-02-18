#ifndef MONITOR_H
#define MONITOR_H

#include <stdatomic.h> 
#include <stdbool.h>
#include <pthread.h> 
#include "protocol_headers.h"

#define MAX_ALERTS 50 
#define ALERT_MSG_LEN 200

/*
Avg = (Current time * alpha) + (old average * (1 - alpha))
Alpha (Smoothing Factor) = 2 / (N + 1)
8 <= N <= 21, in this case N = 19
The reason why N is within these boundaries is because smaller N values 
allows for short term events (such as sniffing) as it increases the indicator's 
sensitivity to recent fluctuations hence more accuracy.  
*/
#define EMA_ALPHA 0.1f

typedef struct { 
    // accumulators that reset to 0 every second by the stats thread 
    atomic_long acc_packets;
    atomic_long acc_bytes; 
    atomic_long acc_matches; 
    atomic_long acc_drops; 

    // rea; time gauges 
    _Atomic double current_mbps; 
    _Atomic double current_pps; 

    // lifetime total 
    atomic_long lifetime_packets; 
    atomic_long lifetime_bytes; 
    atomic_long lifetime_matches; 
    atomic_long lifetime_drops; 

    // atomic_long worker_load[NUM_WORKERS]; // percentage usage of each worker thread
    atomic_long worker_pps[NUM_WORKERS]; 
    
    /*
    Uses EMA calculation to keep track of avgs. The times are for how long a worker
    thread spends in the search_packet() function in sniffer.c 
    */ 
    _Atomic double worker_avg_algo[NUM_WORKERS];
    _Atomic double worker_avg_wait[NUM_WORKERS]; 
    _Atomic double worker_avg_hash[NUM_WORKERS]; 


    
    _Atomic bool engine_active; 

    // flow table trackers 
    atomic_long active_flows; 
    const long max_flow_capacity; 
} engine_stats_t; 

extern engine_stats_t engine_metrics; 

typedef struct { 
    char message[ALERT_MSG_LEN]; 
    long timestamp; 
    int severity; // 0 = INFO, 1 = MATCH, 2 = ERROR
} alert_t; 

extern alert_t alert_queue[MAX_ALERTS]; 
extern int alert_head; 
extern int alert_tail; 
extern pthread_mutex_t alert_lock; 

void start_ui_thread(); 
void add_alert(int severity, const char *msg); 

#endif