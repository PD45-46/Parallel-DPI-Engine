#ifndef INGRESS_H 
#define INGRESS_H 

/*

Directly using AF_PACKET so that the kernal writes the packet into a 
frame in the circular ring buffer that can also be accessed by the sniffer. 
This way the number of copying is reduced, and any memory copy is now only 
from User-mem to User-mem rather than Kernal-mem to User-mem (which is slower
since it involves syscalls, privilege changes and context switching). Hence the
sniffer should be able to perform much faster in comparison.  

Note: 
I could just use libcap's functions to enable zero copy but I want to 
challenge myself and build the tool that I need from scratch. 

Reference: 
https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt
https://docs.securityonion.net/en/2.4/af-packet.html#more-information

*/

#include <linux/if_ether.h>
#include <linux/if_packet.h> 
#include <net/if.h> 
#include <sys/mman.h> 
#include <stdint.h> 

#define CONF_RING_FRAMES 4096 
#define CONF_FRAME_SIZE 2048
#define CONF_BLOCK_SIZE 4096
#define CONF_BLOCK_NR ((CONF_FRAME_SIZE * CONF_RING_FRAMES) / CONF_BLOCK_SIZE) 

#define FANOUT_GROUP_ID 0x1234

typedef struct { 
    int socket_fd; 
    uint8_t *map;                   // start of mmap mem 
    struct tpacket_req ring_req; 
    struct iovec *rd;               // array of ptrs to each frame in the ring 
    int current_frame; 
} af_packet_handle_t; 

af_packet_handle_t* setup_af_packet(const char *interface); 
void teardown_af_packet(af_packet_handle_t *h); 

#endif 