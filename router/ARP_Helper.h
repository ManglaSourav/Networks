#ifndef ARP_Helper
#define ARP_helper

typedef struct ARP_Cache
{
    struct ARP_Cache *next;
    uint32_t ip;
    unsigned char mac_addr[6];
} ARP_Cache;

typedef struct Wait_List
{
    struct Wait_List *next;
    uint8_t *packet;
    unsigned int len;
} Wait_List;

typedef struct ARP_Buf
{
    struct ARP_Buf *next;
    Wait_List head;
    uint32_t ip;
} ARP_Buf;

unsigned char *entry_exists_in_cache(ARP_Cache *head, uint32_t ip);
void insert_ARPCache_Entry(ARP_Cache *head, uint32_t ip, unsigned char *addr);
ARP_Buf *insert_ARPBuf_Entry(ARP_Buf *head, uint32_t ip);
ARP_Buf *entry_exists_in_buf(ARP_Buf *head, uint32_t ip);
void wait_in_queue(ARP_Buf *entry, uint8_t *packet, unsigned int length);
uint8_t *remove_from_queue(ARP_Buf *entry, unsigned int *length);

#endif
