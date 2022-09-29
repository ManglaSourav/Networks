#ifndef ARP_CACHE
#define ARP_CACHE

typedef struct ARP_Cache {
	uint32_t ip;
	unsigned char addr[6];
	struct ARP_Cache *next;
} ARP_Cache;

void insertEntry(ARP_Cache *head, uint32_t ip, unsigned char* addr);
unsigned char*  checkExists(ARP_Cache *head, uint32_t ip);

#endif
