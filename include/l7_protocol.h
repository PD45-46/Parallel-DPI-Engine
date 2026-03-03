#ifndef L7_PROTOCOL 
#define L7_PROTOCOL 

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>

typedef enum { 
    PROTO_UNKNOWN, 
    PROTO_HTTP, 
    PROTO_TLS, 
    PROTO_DNS 
} l7_proto_t; 

l7_proto_t identify_l7_protocol(unsigned char *packet_start, uint32_t len); 

#endif