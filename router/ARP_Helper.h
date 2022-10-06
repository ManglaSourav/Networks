#ifndef ARP_Helper
#define ARP_helper

typedef struct ARP_Cache
{
    uint32_t ip;
    unsigned char addr[6];
    struct ARP_Cache *next;
} ARP_Cache;

typedef struct Waiting_List
{
    uint8_t *packet /* lent */;
    unsigned int len;
    struct Waiting_List *next;
} Waiting_List;

typedef struct ARP_Buffer
{
    uint32_t ip;
    Waiting_List head;
    struct ARP_Buffer *next;
} ARP_Buffer;

void insertEntry(ARP_Cache *head, uint32_t ip, unsigned char *addr);
unsigned char *checkExists(ARP_Cache *head, uint32_t ip);

ARP_Buffer *checkExistsBuf(ARP_Buffer *head, uint32_t ip);
void deleteIP(ARP_Buffer *head, uint32_t ip);
ARP_Buffer *insertNewEntry(ARP_Buffer *head, uint32_t ip);

void queueWaiting(ARP_Buffer *spot, uint8_t *packet, unsigned int len);
uint8_t *extractPacket(ARP_Buffer *spot, unsigned int *len);

#endif
