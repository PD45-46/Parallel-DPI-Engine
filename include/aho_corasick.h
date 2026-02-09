#ifndef AHO_CORASICK_H
#define AHO_CORASICK_H

#define MAX_STATES 1000   // total number of states in the trie
#define ALPHABET_SIZE 256 // every possible byte value

typedef struct { 
    int next_state[ALPHABET_SIZE]; // transitions for each byte value
    int failure_link;              // failure link for Aho-Corasick algorithm (where to go if no match)
    int output;                    // pattern index found
} ACNode; 

ACNode trie[MAX_STATES]; // the trie itself
int state_count = 1;     // init with one state (the root -- index 0)

// void insert_pattern(const char* pattern, int pattern_id);

#endif