#ifndef AHO_CORASICK_H
#define AHO_CORASICK_H

#define MAX_STATES 1024   // total number of states in the trie
#define ALPHABET_SIZE 256 // every possible byte value

typedef struct { 
    int next_state[ALPHABET_SIZE]; // transitions for each byte value
    int failure_link;              // failure link for Aho-Corasick algorithm (where to go if no match)
    int dict_link;                 // dictionary link for output patterns -- points to the next valid pattern
    int output;                    // pattern index found
} ACNode; 

extern ACNode trie[MAX_STATES]; // the trie itself
extern int state_count;     // init with one state (the root -- index 0)



#endif