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
    double local_mbps = atomic_load(&current_mbps); 
    long life_pkts = atomic_load(&lifetime_packets); 
    long drops = atomic_load(&total_packets_dropped); 
    long life_match = atomic_load(&total_matches_found); 

    // stats col 1 
    mvwprintw(win, 3, 4, "Lifetime Packets Processed:  %ld", life_pkts);
    mvwprintw(win, 4, 4, "Bytes Scanned TO CHANGE... : %.2fMB", (double)atomic_load(&total_bytes_scanned) / (1024.0 * 1024.0));

    // stats col 2 
    mvwprintw(win, 3, 45, "Lifetime Matches Found:        %ld", life_match); 
    mvwprintw(win, 4, 45, "Packets Dropped TO CHANGE... : %ld", drops);

    // throughput bar
    mvwprintw(win, 6, 4, "Network Load:");
    wattron(win, COLOR_PAIR(COLOUR_GOOD)); 
    int bars = (int)(local_mbps / 5); 
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