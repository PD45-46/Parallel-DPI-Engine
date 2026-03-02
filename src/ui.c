#include <ncurses.h> 
#include <unistd.h> 
#include <pthread.h> 
#include <time.h> 
#include <stdio.h> 
#include <stdbool.h> 
#include "../include/aho_corasick.h"
#include "../include/monitor.h" 

#define COLOUR_DEFAULT 1 
#define COLOUR_HEADER 2 
#define COLOUR_CRITICAL 3
#define COLOUR_GOOD 4 
#define COLOUR_ALERT 5

static volatile bool keep_running = true; 

void draw_dashboard(WINDOW *win); 
void draw_alerts(WINDOW *win);
void draw_sniffer_info(WINDOW *win); 
void draw_worker_info(WINDOW *win); 
void draw_options_keys(WINDOW *win); 

/**
 * @brief Loop for making sure all elemnets of the TUI are displayed 
 *        in a dynamic manner, in accordance to changing terminal sizes.  
 * 
 * @param arg nothing of importance 
 * @return void* nothing of importance 
 */
void *ui_loop(void *arg) { 

    // unused argument
    (void)arg; 

    // init ncurses 
    initscr(); 
    cbreak(); 
    noecho(); 
    curs_set(0); 
    start_color(); 
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE); 
    use_default_colors(); 

    // colour pairs for foreground and background 
    init_pair(COLOUR_DEFAULT, COLOR_WHITE, -1); 
    init_pair(COLOUR_HEADER, COLOR_BLACK, COLOR_CYAN);
    init_pair(COLOUR_CRITICAL, COLOR_RED, -1);
    init_pair(COLOUR_GOOD, COLOR_GREEN, -1);
    init_pair(COLOUR_ALERT, COLOR_YELLOW, -1); 

    // create windows 
    int height_dash_log = 12;
    int half_width = COLS / 2; 
    int height_win_sniffer_info = 18; 
    int height_win_worker_info = 7 + NUM_WORKERS; 
    // int height_options_keys = 3; 
    

    WINDOW *win_dash = newwin(height_dash_log, half_width, 0, 0);
    WINDOW *win_log = newwin(height_dash_log + height_win_sniffer_info, COLS - half_width, 0, half_width);
    WINDOW *win_sniffer_info = newwin(height_win_sniffer_info, half_width, height_dash_log, 0);
    WINDOW *win_worker_info = newwin(height_win_worker_info, COLS, height_dash_log + height_win_sniffer_info, 0); 
    // WINDOW *win_options_keys = newwin(height_options_keys, COLS, height_dash_log + height_win_sniffer_info + height_win_worker_info, 0); 
    

    // ui loop 
    while(keep_running) { 
        int ch = getch(); 
        if(ch == 'q') { 
            keep_running = false; 
        } else if(ch == KEY_RESIZE) { 
            erase(); 
            refresh(); 

            delwin(win_dash); 
            delwin(win_log); 
            delwin(win_sniffer_info);
            delwin(win_worker_info); 
            // delwin(win_options_keys); 

            half_width = COLS / 2; 

            win_dash = newwin(height_dash_log, half_width, 0, 0);
            win_log = newwin(height_dash_log + height_win_sniffer_info, COLS - half_width, 0, half_width);
            win_sniffer_info = newwin(height_win_sniffer_info, half_width, height_dash_log, 0);
            win_worker_info = newwin(height_win_worker_info, COLS, height_dash_log + height_win_sniffer_info, 0); 
            // win_options_keys = newwin(height_options_keys, COLS, height_dash_log + height_win_sniffer_info + height_win_worker_info, 0); 
        }

        // clear windows to redraw
        werase(win_dash); 
        werase(win_log);
        werase(win_sniffer_info); 
        werase(win_worker_info); 
        // werase(win_options_keys); 

        // draw box boarders 
        box(win_dash, 0, 0);
        box(win_log, 0, 0);
        box(win_sniffer_info, 0, 0); 
        box(win_worker_info, 0, 0); 
        // box(win_options_keys, 0, 0); 

        // draw content 
        draw_dashboard(win_dash);
        draw_alerts(win_log);
        draw_sniffer_info(win_sniffer_info); 
        draw_worker_info(win_worker_info); 
        // draw_options_keys(win_options_keys); 

        // push changes to screen 
        wrefresh(win_dash); 
        wrefresh(win_log); 
        wrefresh(win_sniffer_info); 
        wrefresh(win_worker_info); 
        // wrefresh(win_options_keys); 

        // stall 
        napms(100);

    }

    delwin(win_dash); 
    delwin(win_log); 
    delwin(win_sniffer_info);
    delwin(win_worker_info);
    // delwin(win_options_keys); 
    endwin(); 
    return NULL; 
}

/**
 * @brief Creates display elements for the dashboard window. 
 * 
 * @param win The WINDOW* in which the following elements are 
 *            going to be placed in. 
 */
void draw_dashboard(WINDOW *win) { 

    // title 
    wattron(win, COLOR_PAIR(COLOUR_HEADER)); 
    mvwprintw(win, 1, 2, " DIP ENGINE - MONITORING ACTIVE... "); 
    wattroff(win, COLOR_PAIR(COLOUR_HEADER)); 

    // get atomics safely 
    long total_bytes = atomic_load(&engine_metrics.lifetime_bytes); 
    long total_packets = atomic_load(&engine_metrics.lifetime_packets); 
    long total_drops = atomic_load(&engine_metrics.lifetime_drops); 
    long total_matches = atomic_load(&engine_metrics.lifetime_matches); 
    double current_mbps = atomic_load(&engine_metrics.current_mbps); 
    long current_active_flows = atomic_load(&engine_metrics.active_flows); 
    long max = engine_metrics.max_flow_capacity; 

    // stats col 1 
    mvwprintw(win, 3, 4, "Lifetime Packets Processed:  %ld", total_packets);
    mvwprintw(win, 4, 4, "Lifetime Matches Found:      %ld", total_matches); 
    mvwprintw(win, 5, 4, "Information Maliciousness:   %.2f%%", ((double)total_matches / (double)total_packets) * 100.0); 
    // stats col 2 
    mvwprintw(win, 3, 45, "Total Bytes Scanned:        %ld", total_bytes);
    mvwprintw(win, 4, 45, "Packet Sniffing Speed:      %.2fMbps", current_mbps);
    mvwprintw(win, 5, 45, "Lifetime Packet Drops:      %ld", total_drops);

    // flow capcity bar 
    double flow_capacity = (max > 0) ? ((double)current_active_flows / max) * 100.0 : 0.0; 
    int max_bar_width = 40; 
    int bars_to_fill = (int)((flow_capacity / 100.0) * max_bar_width); 

    if(bars_to_fill > max_bar_width) bars_to_fill = max_bar_width; 

    mvwprintw(win, 9, 4, "Flow Table Capacity: ["); 
    int bar_start_col = 26; 

    int colour_pair = COLOUR_GOOD; 
    if(flow_capacity > 80.0) colour_pair = COLOUR_CRITICAL; 
    else if(flow_capacity > 50.0) colour_pair = COLOUR_ALERT;
    
    wattron(win, COLOR_PAIR(colour_pair)); 
    for(int i = 0; i < max_bar_width; i++) { 
        if(i < bars_to_fill) { 
            mvwaddch(win, 9, bar_start_col + i, '|'); 
        } else { 
            mvwaddch(win, 9, bar_start_col + i, ' '); 
        }
    }
    wattroff(win, COLOR_PAIR(colour_pair));
    mvwprintw(win, 9, bar_start_col + max_bar_width, "] %.2f%% (%ld/%ld)", flow_capacity, current_active_flows, max);
}

/**
 * @brief Displays all the alerts being sent from the sniffer. 
 * 
 * @param win The WINDOW* in which the following elements are 
 *            going to be placed in. 
 */
void draw_alerts(WINDOW *win) { 

    wattron(win, COLOR_PAIR(COLOUR_HEADER));
    mvwprintw(win, 1, 2, "[ ALERT LOG ]"); 
    wattroff(win, COLOR_PAIR(COLOUR_HEADER));

    pthread_mutex_lock(&alert_lock); 

    int y = 3; 
    int i = alert_tail; 

    while(i != alert_head && y < 28) { 
        mvwprintw(win, y++, 4, "> %s", alert_queue[i].message); 
        i = (i + 1) % MAX_ALERTS; 
    }
    pthread_mutex_unlock(&alert_lock); 
}


/** 
 * @brief Displays general info about the program. 
 * 
 * @param win The WINDOW* in which the following elements are 
 *            going to be placed in. 
 */
void draw_sniffer_info(WINDOW *win) { 

    wattron(win, COLOR_PAIR(COLOUR_HEADER)); 
    mvwprintw(win, 1, 2, "[ SNIFFER INFO ]");
    wattroff(win, COLOR_PAIR(COLOUR_HEADER));

    int active_flows = atomic_load(&engine_metrics.active_flows); 
    // int total_p = atomic_load(&engine_metrics.lifetime_packets); 
    // int tcp_p = atomic_load(&engine_metrics.lifetime_tcp_p);
    // double tcp_percentage = (total_p > 0) ? ((double)tcp_p / total_p) * 100 : 0; 
    double tcp_percentage = 50; 

    mvwprintw(win, 3, 4, "[INTERFACE]: lo (loopback)");
    mvwprintw(win, 3, 32, "[DRIVER]: AF_PACKET -- ZERO COPY"); 
    
    mvwprintw(win, 4, 4, "[RING BUFFER]: {percentage...} | {total frames} | {kernal drops}"); 

    mvwprintw(win, 6, 4, "[CPU AFFINITY MAP]:"); 
    mvwprintw(win, 7, 6, "CORE 0 - OS/MAIN");
    mvwprintw(win, 8, 6, "CORE 1 - TUI INTERFACE");
    mvwprintw(win, 7, 35, "CORE 2 to CORE %d - WORKERS", 2 + NUM_WORKERS);
    mvwprintw(win, 8, 35, "CORE %d - STATS HANDLER", 3 + NUM_WORKERS);
    
    

    mvwprintw(win, 10, 4, "[FLOW ENGINE]:");
    mvwprintw(win, 11, 6, "ACTIVE FLOWS: %d / %d", active_flows, MAX_TOTAL_FLOWS); 

    mvwprintw(win, 12, 6, "TCP TRAFFIC: %.1f%%", tcp_percentage); 
    mvwprintw(win, 12, 35, "UDP/OTHER: %.1f%%", 100.0 - tcp_percentage); 
    
    mvwprintw(win, 14, 4, "[TRIE STATUS]: "); 
    mvwprintw(win, 15, 6, "PATTERNS LOADED: %d", loaded_count); 
    mvwprintw(win, 15, 35, "TOTAL STATES: %d", state_count); 


}



/**
 * @brief Dedicated information about the worker threads
 * 
 * @param win The WINDOW* in which the following elements are 
 *            going to be placed in. 
 */
void draw_worker_info(WINDOW *win) { 

    wattron(win, COLOR_PAIR(COLOUR_HEADER)); 
    mvwprintw(win, 1, 2, "[ WORKER LATENCY ]");
    wattroff(win, COLOR_PAIR(COLOUR_HEADER));

    int max_bar_width = 110; 

    mvwprintw(win, 3, 4, "[LEGEND]: GREEN -- ALGO PROCESSING TIME | YELLOW -- HASH LOOKUP TIME | RED -- REMAINING TIME SPENT IN WORKER LOOP | EXPONENTIAL MOVING AVERAGES (EMA)");

    for(int i = 0; i < NUM_WORKERS; i++) { 

        double algo_time = atomic_load(&engine_metrics.worker_avg_algo[i]); 
        double wait_time = atomic_load(&engine_metrics.worker_avg_wait[i]); 
        double hash_time = atomic_load(&engine_metrics.worker_avg_hash[i]); 

        double total_time = algo_time + wait_time + hash_time; 
        if(total_time <= 0) total_time = 1.; 

        int bar_start_col = 18; 
        int current_row = 5 + i; 

        int algo_bars = (int)((algo_time / total_time) * max_bar_width);
        int hash_bars = (int)((hash_time / total_time) * max_bar_width);
        int wait_bars = max_bar_width - (algo_bars + hash_bars); 

        int col = 6; 
        mvwprintw(win, current_row, col, "[WORKER %d]: [", i);
        col = bar_start_col + 1; 
        
        wattron(win, COLOR_PAIR(COLOUR_GOOD));
        for(int j = 0; j < algo_bars; j++) mvwaddch(win, current_row, col++, '|');
        wattroff(win, COLOR_PAIR(COLOUR_GOOD)); 

        wattron(win, COLOR_PAIR(COLOUR_ALERT));
        for(int j = 0; j < hash_bars; j++) mvwaddch(win, current_row, col++, '|');
        wattroff(win, COLOR_PAIR(COLOUR_ALERT)); 

        wattron(win, COLOR_PAIR(COLOUR_CRITICAL));
        for(int j = 0; j < wait_bars; j++) mvwaddch(win, current_row, col++, '|');
        wattroff(win, COLOR_PAIR(COLOUR_CRITICAL)); 


        mvwprintw(win, current_row, bar_start_col + max_bar_width, "]");
    }
}
 


void draw_options_keys(WINDOW* win) { 

    mvwprintw(win, 1, 2, "[ Q: Quit ]");
    mvwprintw(win, 1, 16, "[ P: Pause ]");
    mvwprintw(win, 1, 30, "[ R: Reset ]");
    mvwprintw(win, 1, 44, "[ C: Clear Alerts ]");
    mvwprintw(win, 1, 66, "[ ETC... ]"); 

}


/**
 * @brief Creates the thread for displaying the UI so that other CPU cores 
 *        are taking some of this program's load. 
 * 
 */
void start_ui_thread() { 
    pthread_t thread_id; 
    pthread_create(&thread_id, NULL, ui_loop, NULL);
} 