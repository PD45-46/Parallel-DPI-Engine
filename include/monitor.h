#ifndef MONITOR_H
#define MONITOR_H

#include <stdatomic.h> 
#include <stdbool.h>
#include <pthread.h> 

#define MAX_ALERTS 50 
#define ALERT_MSG_LEN 200

extern atomic_long total_bytes_scanned;
extern atomic_long total_packets_processed;
extern atomic_long total_matches_found;
extern atomic_long total_packets_dropped;
extern double current_mbps; // Calculated in stats thread

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