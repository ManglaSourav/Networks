
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "sr_router.h"
#include "ARP_Buffer.h"

//returns the node if exists, NULL if does not
ARP_Buffer *checkExistsBuf(ARP_Buffer *head, uint32_t ip) {
	ARP_Buffer *curr = head;
	while(curr->next != NULL && (curr->next)->ip != ip) {
		curr = curr->next;
	}

	if(curr->next != NULL) {
		return curr->next; //we found it.
	}

	return NULL;
}

void deleteIP(ARP_Buffer *head, uint32_t ip);

//inserts process at beginning of linked list
ARP_Buffer *insertNewEntry(ARP_Buffer *head, uint32_t ip) {
    ARP_Buffer *new = (ARP_Buffer *) malloc(sizeof(ARP_Buffer));
    new->ip = ip;
    new->head.next = NULL;

	ARP_Buffer *temp = head->next;
	head->next = new;
	new->next = temp;
    
    return new;
}

void queueWaiting(ARP_Buffer *spot, uint8_t *packet, unsigned int len) {
    Waiting_List *new = (Waiting_List *) malloc(sizeof(Waiting_List));
    new->packet = (uint8_t *) malloc(len);
    memcpy(new->packet, packet, len);
    new->len = len;

    Waiting_List *temp = spot->head.next;
    spot->head.next = new;
	new->next = temp;
}

// It is the responsibility of the caller to free the packet after processing. 
uint8_t *extractPacket(ARP_Buffer *spot, unsigned int *len) {
    Waiting_List *temp = spot->head.next;
    if(temp == NULL) {
        return NULL;
    }
    uint8_t *packet = temp->packet;
    *len = temp->len;

    spot->head.next = temp->next;
    free(temp);

    return packet;
}
