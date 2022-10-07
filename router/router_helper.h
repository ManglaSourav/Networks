#ifndef ROUTER_HELPER
#define ROUTER_HELPER

struct icmp_hdr
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t data;
} __attribute__((packed));

#ifndef ICMP_REP
#define ICMP_REP 0
#endif

#ifndef ICMP_REQ
#define ICMP_REQ 8
#endif

u_short cksum(u_short *buf, int count);
uint16_t icmp_cksum(uint16_t *addr, int count);

#endif
