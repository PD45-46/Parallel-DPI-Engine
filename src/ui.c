#include <ncurses.h> 
#include <unistd.h> 
#include <pthread.h> 
#include <time.h> 
#include <stdio.h> 
#include <stdbool.h> 
#include "../include/monitor.h" 

#define COLOUR_DEFAULT 1 
#define COLOUR_HEADER 2 
#define COLOUR_ALERT 3
#define COLOUR_GOOD 4 

static volatile bool keep_running = true; 

void draw_dashboard(WINDOW *win); 
void draw_alerts(WINDOW *win);

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
    init_pair(COLOUR_ALERT, COLOR_RED, -1);
    init_pair(COLOUR_GOOD, COLOR_GREEN, -1);

    // create windows 
    int height_dash_log = 12;
    int half_width = COLS / 2; 
    

    WINDOW *win_dash = newwin(height_dash_log, half_width, 0, 0);
    WINDOW *win_log = newwin(height_dash_log, COLS - half_width, 0, half_width);
    

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

            half_width = COLS / 2; 

            win_dash = newwin(height_dash_log, half_width, 0, 0);
            win_log = newwin(height_dash_log, COLS - half_width, 0, half_width);
        }

        // clear windows to redraw
        werase(win_dash); 
        werase(win_log);
        
        // draw box boarders 
        box(win_dash, 0, 0);
        box(win_log, 0, 0);

        // draw content 
        draw_dashboard(win_dash);
        draw_alerts(win_log);

        // push changes to screen 
        wrefresh(win_dash); 
        wrefresh(win_log); 

        // stall 
        napms(100);

    }

    delwin(win_dash); 
    delwin(win_log); 
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

    // stats col 1 
    mvwprintw(win, 3, 4, "Lifetime Packets Processed:  %ld", total_packets);
    mvwprintw(win, 4, 4, "Lifetime Matches Found:      %ld", total_matches); 
    mvwprintw(win, 5, 4, "Packet Maliciousness:        %.2f%%", ((double)total_matches / (double)total_packets) * 100.0); 
    // stats col 2 
    mvwprintw(win, 3, 45, "Total Bytes Scanned:        %ld", total_bytes);
    mvwprintw(win, 4, 45, "Packet Sniffing Speed:      %.2fMbps", current_mbps);
    mvwprintw(win, 5, 45, "Lifetime Packet Drops:      %ld", total_drops);

    // throughput bar
    mvwprintw(win, 7, 4, "Network Load: [");
    wattron(win, COLOR_PAIR(COLOUR_GOOD)); 
    int bars = (int)(current_mbps / 5); 
    if(bars > 30) bars = 30; 
    for(int i = 0; i < bars; i++) { 
        mvwaddch(win, 6, 18+i, '|'); 
    }  
    wattroff(win, COLOR_PAIR(COLOUR_GOOD)); 
}

void draw_alerts(WINDOW *win) { 

    mvwprintw(win, 1, 2, "[ ALERT LOG ]"); 

    pthread_mutex_lock(&alert_lock); 

    int y = 2; 
    int i = alert_tail; 

    while(i != alert_head && y < 8) { 
        mvwprintw(win, y++, 2, "> %s", alert_queue[i].message); 
        i = (i + 1) % MAX_ALERTS; 
    }
    pthread_mutex_unlock(&alert_lock); 
}

void start_ui_thread() { 
    pthread_t thread_id; 
    pthread_create(&thread_id, NULL, ui_loop, NULL);
} 