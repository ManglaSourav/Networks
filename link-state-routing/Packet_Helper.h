#ifndef ICMP_REP
#define ICMP_REP 0
#endif

#ifndef ICMP_REQ
#define ICMP_REQ 8
#endif

#ifndef Packet_Helper
#define Packet_Helper

typedef struct Wait_List
{
    uint8_t *packet;
    unsigned int len;
    struct Wait_List *next;
} Wait_List;

typedef struct ARP_Buf
{
    uint32_t ip;
    Wait_List head;
    struct ARP_Buf *next;
} ARP_Buf;

typedef struct ARP_Cache
{
    uint32_t ip;
    unsigned char addr[6];
    struct ARP_Cache *next;
} ARP_Cache;

struct icmp_hdr
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t data;
} __attribute__((packed));

void insert_ARPCache_Entry(ARP_Cache *head, uint32_t ip, unsigned char *addr);
unsigned char *entry_exists_in_cache(ARP_Cache *head, uint32_t ip);
u_short cksum(u_short *buf, int count);
uint16_t icmp_cksum(uint16_t *addr, int count);
ARP_Buf *insert_ARPBuf_Entry(ARP_Buf *head, uint32_t ip);
ARP_Buf *entry_exists_in_buf(ARP_Buf *head, uint32_t ip);
void wait_in_queue(ARP_Buf *entry, uint8_t *packet, unsigned int length);
uint8_t *remove_from_queue(ARP_Buf *entry, unsigned int *len);
// TODO
uint8_t *extractPacket(ARP_Buf *spot, unsigned int *len);

#endif
