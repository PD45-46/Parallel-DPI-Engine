// #include "aho_corasick.h"

// /** 
//  * @brief Inserts a pattern into the Aho-Corasick trie. 
//  */
// void insert_pattern(const char* pattern, int pattern_id) {
//     int current_state = 0; // start at root 
//     for(int i = 0; i < pattern[i] != '\0'; i++) { 
//         unsigned char byte = pattern[i]; 
//         if(trie[current_state].next_state[byte] == -1) { 
//             // create a new state if dne 
//             for(int j = 0; j < ALPHABET_SIZE; j++) {
//                 trie[state_count].next_state[j] = -1; // initialize new state
//             }
//             trie[state_count].output = 0; 
//             trie[current_state].next_state[byte] = state_count++; 
//         }
//         current_state = trie[current_state].next_state[byte];
//     }
//     trie[current_state].output = pattern_id; // marks as a match
// }