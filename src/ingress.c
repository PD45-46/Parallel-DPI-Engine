#include "../include/ingress.h"
#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <stdint.h> 
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>



af_packet_handle_t* setup_af_packet(const char *interface) { 
    af_packet_handle_t *h = calloc(1, sizeof(af_packet_handle_t)); 

    // create RAW AF_PACKET socket 
    h->socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); 
    if(h->socket_fd < 0) { 
        perror("socket"); 
        return NULL; 
    }

    // set version 
    int version = TPACKET_V2; 
    setsockopt(h->socket_fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)); 

    // def the ring request 
    h->ring_req.tp_block_size = CONF_BLOCK_SIZE; 
    h->ring_req.tp_frame_size = CONF_FRAME_SIZE;
    h->ring_req.tp_block_nr   = CONF_BLOCK_NR;
    h->ring_req.tp_frame_nr   = CONF_RING_FRAMES;
    
    // tell kernal to allocate ring 
    if(setsockopt(h->socket_fd, SOL_PACKET, PACKET_RX_RING, &h->ring_req, sizeof(h->ring_req)) < 0) { 
        perror("setsockopt RX_RING"); 
        return NULL; 
    }

    // mem map -> maps kernal's ring buffer into processes memory space  
    size_t total_mem = h->ring_req.tp_block_size * h->ring_req.tp_block_nr; 
    h->map = mmap(NULL, total_mem, PROT_READ | PROT_WRITE, MAP_SHARED, h->socket_fd, 0); 
    if(h->map == MAP_FAILED) { 
        perror("mmap"); 
        return NULL; 
    }

    // set up frame pointers 
    h->rd = malloc(h->ring_req.tp_frame_nr * sizeof (struct iovec)); 
    for(unsigned int i = 0; i < h->ring_req.tp_frame_nr; ++i) { 
        h->rd[i].iov_base = h->map + (i * h->ring_req.tp_frame_size); 
        h->rd[i].iov_len = h->ring_req.tp_frame_size; 
    }

    // bind to interface
    struct sockaddr_ll sll = { 
        .sll_family = AF_PACKET, 
        .sll_protocol = htons(ETH_P_ALL), 
        .sll_ifindex = if_nametoindex(interface)
    }; 
    bind(h->socket_fd, (struct sockaddr *)&sll, sizeof(sll)); 

    return h;  
}




void teardown_af_packet(af_packet_handle_t *h) { 
    if(!h) return; 
    munmap(h->map, h->ring_req.tp_block_size * h->ring_req.tp_block_nr); 
    close(h->socket_fd); 
    free(h->rd); 
    free(h); 
}