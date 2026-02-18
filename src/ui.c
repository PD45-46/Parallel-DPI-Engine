#include <ncurses.h> 
#include <unistd.h> 
#include <pthread.h> 
#include <time.h> 
#include <stdio.h> 
#include <stdbool.h> 
#include "../include/monitor.h" 

#define COLOUR_DEFAULT 1 
#define COLOUR_HEADER 2 
#define COLOUR_CRITICAL 3
#define COLOUR_GOOD 4 
#define COLOUR_ALERT 5

static volatile bool keep_running = true; 

void draw_dashboard(WINDOW *win); 
void draw_alerts(WINDOW *win);
void draw_worker_info(WINDOW *win); 

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
    int height_win_worker_info = 12; 
    

    WINDOW *win_dash = newwin(height_dash_log, half_width, 0, 0);
    WINDOW *win_log = newwin(height_dash_log, COLS - half_width, 0, half_width);
    WINDOW *win_worker_info = newwin(height_win_worker_info, COLS, height_dash_log, 0); 
    

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
            delwin(win_worker_info); 

            half_width = COLS / 2; 

            win_dash = newwin(height_dash_log, half_width, 0, 0);
            win_log = newwin(height_dash_log, COLS - half_width, 0, half_width);
            win_worker_info = newwin(height_win_worker_info, COLS, height_dash_log, 0); 
        }

        // clear windows to redraw
        werase(win_dash); 
        werase(win_log);
        werase(win_worker_info); 

        // draw box boarders 
        box(win_dash, 0, 0);
        box(win_log, 0, 0);
        box(win_worker_info, 0, 0); 

        // draw content 
        draw_dashboard(win_dash);
        draw_alerts(win_log);
        draw_worker_info(win_worker_info); 

        // push changes to screen 
        wrefresh(win_dash); 
        wrefresh(win_log); 
        wrefresh(win_worker_info); 

        // stall 
        napms(100);

    }

    delwin(win_dash); 
    delwin(win_log); 
    delwin(win_worker_info);
    endwin(); 
    return NULL; 
}

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
    mvwprintw(win, 9, bar_start_col + max_bar_width, "] %.1f%% (%ld/%ld)", flow_capacity, current_active_flows, max);
}

void draw_alerts(WINDOW *win) { 

    wattron(win, COLOR_PAIR(COLOUR_HEADER));
    mvwprintw(win, 1, 2, "[ ALERT LOG ]"); 
    wattroff(win, COLOR_PAIR(COLOUR_HEADER));

    pthread_mutex_lock(&alert_lock); 

    int y = 3; 
    int i = alert_tail; 

    while(i != alert_head && y < 10) { 
        mvwprintw(win, y++, 4, "> %s", alert_queue[i].message); 
        i = (i + 1) % MAX_ALERTS; 
    }
    pthread_mutex_unlock(&alert_lock); 
}

void draw_worker_info(WINDOW *win) { 

    wattron(win, COLOR_PAIR(COLOUR_HEADER)); 
    mvwprintw(win, 1, 2, "[ WORKER INFO ]");
    wattroff(win, COLOR_PAIR(COLOUR_HEADER));

    int max_bar_width = 20; 

    for(int i = 0; i < NUM_WORKERS; i++) { 

        long worker_pps = atomic_exchange(&engine_metrics.worker_pps[i], 0); 
        double max_expected_pps = GLOBAL_PPS_LIMIT; 
        double percentage = (worker_pps / max_expected_pps) * 100.0; 

        if(percentage > 100.0) percentage = 100.0; 
        int bars_to_fill = (int)((percentage / 100.0) * max_bar_width); 


        int bar_start_col = 17; 
        int current_row = 3 + i; 

        mvwprintw(win, current_row, 4, "[WORKER %d]: [", i);

        int colour_pair = COLOUR_GOOD; 
        if(percentage > 80.0) colour_pair = COLOUR_CRITICAL; 
        else if(percentage > 50.0) colour_pair = COLOUR_ALERT;

        wattron(win, COLOR_PAIR(colour_pair)); 
        for(int j = 0; j < max_bar_width; j++) { 
            if(j < bars_to_fill) { 
                mvwaddch(win, current_row, bar_start_col + j, '|'); 
            } else { 
                mvwaddch(win, current_row, bar_start_col + j, ' '); 
            }
        }
        wattroff(win, COLOR_PAIR(colour_pair));
        mvwprintw(win, current_row, bar_start_col + max_bar_width, "] %.1f%%", percentage);
    }
}
 
void start_ui_thread() { 
    pthread_t thread_id; 
    pthread_create(&thread_id, NULL, ui_loop, NULL);
} 