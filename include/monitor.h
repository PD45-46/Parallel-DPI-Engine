#ifndef MONITOR_H
#define MONITOR_H

#include <stdatomic.h> 
#include <stdbool.h>
#include <pthread.h> 
#include "protocol_headers.h"

#define MAX_ALERTS 50 
#define ALERT_MSG_LEN 200

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

    _Atomic double worker_load[NUM_WORKERS]; // percentage usage of each worker thread
    _Atomic bool engine_active; 
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