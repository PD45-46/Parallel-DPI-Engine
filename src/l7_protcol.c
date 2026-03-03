#include <../include/l7_protocol.h> 
#include <string.h> 

/**
 * @brief Identifies the type of l7 protocol. 
 * 
 * @param packet_start Points to the head of the packet. 
 * @param len Used for safety checks 
 * @return l7_proto_t Enum value to be used in the worker_thread() function. 
 */
l7_proto_t identify_l7_protocol(unsigned char *packet_start, uint32_t len) { 

    if(len < sizeof(struct ethhdr)) return PROTO_UNKNOWN; 


    struct ethhdr *eth = (struct ethhdr *)packet_start; 

    // only allow IPv4
    if(ntohs(eth->h_proto) != ETH_P_IP) return PROTO_UNKNOWN;
    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) return PROTO_UNKNOWN;

    
    struct iphdr *ip = (struct iphdr *)(packet_start + sizeof(struct ethhdr)); 
    uint32_t ip_hdr_len = ip->ihl * 4; 

    // process tcp 
    if(ip->protocol == IPPROTO_TCP) { 
        struct tcphdr *tcp = (struct tcphdr *)((unsigned char *)ip + ip_hdr_len);
        uint32_t tcp_hdr_len = tcp->doff * 4; 
        unsigned char *payload = (unsigned char *)tcp + tcp_hdr_len; 
        uint32_t payload_len = ntohs(ip->tot_len) - ip_hdr_len - tcp_hdr_len; 

        if(payload_len < 4) return PROTO_UNKNOWN; 

        // signature matching 
        if(memcmp(payload, "GET ", 4) == 0 || memcmp(payload, "POST", 4) == 0 || memcmp(payload, "HTTP", 4) == 0) { 
            return PROTO_HTTP; 
        }
        // TLS Handshake starts with 0x16 (handshake), 0x03 (version)
        if(payload[0] == 0x16 && payload[1] == 0x03) { 
            return PROTO_TLS; 
        }
    }

    return PROTO_UNKNOWN; 
}