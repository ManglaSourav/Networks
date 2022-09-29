#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "sr_router.h"
#include "ARP_Cache.h"

//inserts ARP entry at beginning of linked list
void insertEntry(ARP_Cache *head, uint32_t ip, unsigned char* addr) {
	ARP_Cache *new = (ARP_Cache *)malloc(sizeof(ARP_Cache));
	new->ip = ip;
	memcpy(new->addr, addr, sizeof(new->addr));

	ARP_Cache *temp = head->next;
	head->next = new;
	new->next = temp;
}

//returns 1 if exists, 0 if does not. If exists, fill out addr. 
unsigned char* checkExists(ARP_Cache *head, uint32_t ip) {
	ARP_Cache *curr = head;
	while(curr->next != NULL && (curr->next)->ip != ip) {
		curr = curr->next;
	}

	if(curr->next != NULL) {
		//DebugMAC("%d ", curr->next->ip);
		return curr->next->addr; //we found it.
	}

	return NULL;
}
