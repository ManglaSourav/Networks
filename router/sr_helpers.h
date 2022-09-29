#ifndef SR_HELPERS
#define SR_HELPERS

struct icmp_hdr
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t data;
    // not sure if we need the payload.
} __attribute__((packed));

#ifndef ICMP_TYPE_REQ
#define ICMP_TYPE_REQ 8
#endif

#ifndef ICMP_TYPE_REP
#define ICMP_TYPE_REP 0
#endif

// HELPER FUNCTIONS FOR IP
u_short cksum(u_short *buf, int count);
uint16_t icmp_checksum(uint16_t *addr, int count);

// DEBUG FUNCTIONS
void print_arp_header(struct sr_arphdr *arp);
void print_ip_header(struct ip *ip);
void print_arp_cache();
void print_icmp_header(struct icmp_hdr *icmp);

#endif
