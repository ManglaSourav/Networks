#ifndef ARP_BUFFER
#define ARP_BUFFER

typedef struct Waiting_List {
	uint8_t * packet/* lent */;
	unsigned int len;
	struct Waiting_List *next;
} Waiting_List;


typedef struct ARP_Buffer {
	uint32_t ip;
	Waiting_List head;
	struct ARP_Buffer *next;
} ARP_Buffer;



ARP_Buffer *checkExistsBuf(ARP_Buffer *head, uint32_t ip);
void deleteIP(ARP_Buffer *head, uint32_t ip);
ARP_Buffer *insertNewEntry(ARP_Buffer *head,  uint32_t ip);

void queueWaiting(ARP_Buffer *spot, uint8_t *packet, unsigned int len);
uint8_t *extractPacket(ARP_Buffer *spot, unsigned int *len);

#endif
