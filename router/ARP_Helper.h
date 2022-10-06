#ifndef ARP_Helper
#define ARP_helper

typedef struct ARP_Cache
{
    uint32_t ip;
    unsigned char addr[6];
    struct ARP_Cache *next;
} ARP_Cache;

typedef struct Wait_List
{
    uint8_t *packet /* lent */;
    unsigned int len;
    struct Wait_List *next;
} Wait_List;

typedef struct ARP_Buf
{
    uint32_t ip;
    Wait_List head;
    struct ARP_Buf *next;
} ARP_Buf;

void insertEntry(ARP_Cache *head, uint32_t ip, unsigned char *addr);
unsigned char *checkExists(ARP_Cache *head, uint32_t ip);

ARP_Buf *checkExistsBuf(ARP_Buf *head, uint32_t ip);
void deleteIP(ARP_Buf *head, uint32_t ip);
ARP_Buf *insertNewEntry(ARP_Buf *head, uint32_t ip);

void queueWaiting(ARP_Buf *spot, uint8_t *packet, unsigned int len);
uint8_t *extractPacket(ARP_Buf *spot, unsigned int *len);

#endif
