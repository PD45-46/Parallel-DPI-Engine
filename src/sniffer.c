#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>

// Ethernet header (always 14 bytes)
struct sniff_ethernet { 
    u_char ether_dhost[6]; // destination host address
    u_char ether_shost[6]; // source host address
    u_short ether_type;    // IP, ARP, RARP, etc.
};

// IP Header ()
struct sniff_ip { 
    u_char ip_vhl;                 // version << 4 | header length >> 2
    u_char ip_tos;                 // type of service
    u_short ip_len;                 // total length
    u_short ip_id;                  // identification field
    u_short ip_off;                 // fragment offset field
    u_char ip_ttl;                 // time to live
    u_char ip_p;                   // protocol (TCP, UDP, etc.)
    u_short ip_sum;                 // checksum  
    struct in_addr ip_src, ip_dst; // source and dest address
}; 
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f) // IP header length in 32-bit words

// TCP header (variable length, minimum 20 bytes)
struct sniff_tcp { 
    u_short th_sport;     // source port
    u_short th_dport;     // destination port
    u_int32_t th_seq;     // sequence number 
    u_int32_t th_ack;     // acknowledgment number 
    u_char th_offx2;      // data offset, rsvd
    u_char th_flags;      // TCP flags 
    u_short th_win;       // window
    u_short th_sum;       // checksum
    u_short th_urp;       // urgent pointer
};
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4) // TCP header length in 32-bit words


void print_payload(const u_char *payload, int len);
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


// void print_payload(const u_char *payload, int len) { 
//     const u_char *ch = payload; 
//     for(int i = 0; i < len; i++) { 
//         if(isprint(*ch)) { 
//             printf("%c", *ch);
//         } else { 
//             printf(".");
//         }
//         ch++; 
//     }
//     printf("\n");
// }


/** 
 * @brief This function is called every time a packet is captured. 
 */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    const struct sniff_ip *ip_header;
    const struct sniff_tcp *tcp_header;
    const char *payload;

    // Use hardcoded offsets for speed (HFT Style)
    ip_header = (struct sniff_ip*)(packet + 14);
    int size_ip = IP_HL(ip_header) * 4;

    if (size_ip < 20) return;

    if (ip_header->ip_p == IPPROTO_TCP) {
        tcp_header = (struct sniff_tcp*)(packet + 14 + size_ip);
        int size_tcp = TH_OFF(tcp_header) * 4;
        if (size_tcp < 20) return;

        int payload_len = ntohs(ip_header->ip_len) - (size_ip + size_tcp);

        if (payload_len > 0) {
            printf("[%s:%d -> ", inet_ntoa(ip_header->ip_src), ntohs(tcp_header->th_sport));
            printf("%s:%d] Payload: %d bytes\n", inet_ntoa(ip_header->ip_dst), ntohs(tcp_header->th_dport), payload_len);
            
            payload = (u_char *)(packet + 14 + size_ip + size_tcp);
            print_payload(payload, payload_len > 64 ? 64 : payload_len); // Print first 64 chars
        }
    }


    // TODO: Add more 

    /* 
    packet is ptr to raw bytes. 
    Byte 0 - 13: Ethernet header
    Byte 14 - 33: IP header (if Ethernet type is IPv4)
    Byte 34 - 53: TCP header (if IP protocol is TCP)
    */
}

void print_payload(const u_char *payload, int len) {
    const u_char *ch = payload;
    printf("   ");
    for(int i = 0; i < len; i++) {
        if (isprint(*ch)) // If it's a readable character (A, B, 1, @)
            printf("%c", *ch);
        else
            printf("."); // If it's binary data
        ch++;
    }
    printf("\n");
}

int main() { 
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle; 

    // find a default device to capture from 
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL) { 
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 1;
    }

    // open device for live capture (sniffing)
    // 65535 is the maximum packet size to capture (SNAPLEN)
    handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);

    // start the capture loop
    printf("Sniffing on device: %s\n", dev); 
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}