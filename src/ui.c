#include <ncurses.h> 
#include <unistd.h> 
#include <pthread.h> 
#include <time.h> 
#include <stdio.h> 
#include "../include/monitor.h" 

#define COLOUR_DEFAULT 1 
#define COLOUR_HEADER 2 
#define COLOUR_ALERT 3
#define COLOUR_GOOD 4  

void draw_dashboard(WINDOW *win); 
void draw_alerts(WINDOW *win);

void *ui_loop(void *arg) { 

    // init ncurses 
    initscr(); 
    cbreak(); 
    noecho(); 
    curs_set(0); 
    start_color(); 
    use_default_colors(); 

    // colour pairs for foreground and background 
    init_pair(COLOUR_DEFAULT, COLOR_WHITE, -1); 
    init_pair(COLOUR_HEADER, COLOR_BLACK, COLOR_CYAN);
    init_pair(COLOUR_ALERT, COLOR_RED, -1);
    init_pair(COLOUR_GOOD, COLOR_GREEN, -1);

    // create windows 
    int height_log = 10; 
    int height_dash = LINES - height_log; 

    WINDOW *win_dash = newwin(height_dash, COLS, 0, 0);
    WINDOW *win_log = newwin(height_log, COLS, height_dash, 0);
    
    // ui loop 
    while(1) { 
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
        
        // TODO: Implement escape scheme 
    }
    endwin(); 
    return NULL; 
}

void draw_dashboard(WINDOW *win) { 

    // title 
    wattron(win, COLOR_PAIR(COLOUR_HEADER)); 
    mvwprintw(win, 1, 2, " DIP ENGINE - MONITORING ACTIVE... "); 
    wattroff(win, COLOR_PAIR(COLOUR_HEADER)); 

    // get atomics safely 
    long packets = atomic_load(&total_packets_processed); 
    long drops = atomic_load(&total_packets_dropped); 
    long matches = atomic_load(&total_matches_found); 

    // stats col 1 
    mvwprintw(win, 3, 4, "Packets Processed: %ld", packets);
    mvwprintw(win, 4, 4, "Bytes Scanned:     %ld MB", atomic_load(&total_bytes_scanned) / 1024 / 1024);

    // stats col 2 
    mvwprintw(win, 3, 40, "Matches Found:");
    wattron(win, COLOR_PAIR(COLOUR_ALERT) | A_BOLD);
    mvwprintw(win, 3, 55, "%ld", matches); // Highlight matches in RED
    wattroff(win, COLOR_PAIR(COLOUR_ALERT) | A_BOLD);
    mvwprintw(win, 4, 40, "Packets Dropped:   %ld", drops);

    // throughput bar
    mvwprintw(win, 6, 4, "Network Load:");
    wattron(win, COLOR_PAIR(COLOUR_GOOD)); 
    int bars = (packets  % 100) / 5; 
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