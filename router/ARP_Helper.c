#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "sr_router.h"
#include "ARP_Helper.h"

// inserts ARP entry(at the beginning) into the cache for future ARP request resolution
void insert_ARPCache_Entry(ARP_Cache *head, uint32_t ip, unsigned char *addr)
{
    ARP_Cache *new = (ARP_Cache *)malloc(sizeof(ARP_Cache));
    memcpy(new->mac_addr, addr, sizeof(new->mac_addr));
    new->ip = ip;

    // attaching new node to the head of the linked list
    ARP_Cache *t = head->next;
    head->next = new;
    new->next = t;
}

// if entry present in the cache, return the mac address otherwise return null
unsigned char *entry_exists_in_cache(ARP_Cache *head, uint32_t ip)
{
    ARP_Cache *temp = head;
    while (temp->next != NULL && (temp->next)->ip != ip)
        temp = temp->next;

    if (temp->next != NULL)
        // TODO: DebugMAC("%d ", temp->next->ip);
        //  found the entry return the cache
        return temp->next->mac_addr;

    return NULL;
}

// inserts request to the list at the beginning
ARP_Buf *insert_ARPBuf_Entry(ARP_Buf *head, uint32_t ip)
{
    ARP_Buf *new = (ARP_Buf *)malloc(sizeof(ARP_Buf));
    new->head.next = NULL;
    new->ip = ip;
    ARP_Buf *t = head->next;
    head->next = new;
    new->next = t;
    return new;
}

// search ARP request on the basis of ip, if we found it return the buffer node.
ARP_Buf *entry_exists_in_buf(ARP_Buf *head, uint32_t ip)
{
    ARP_Buf *temp = head;
    while (temp->next != NULL && (temp->next)->ip != ip)
        temp = temp->next;

    if (temp->next != NULL)
        return temp->next;
    return NULL;
}

// put a packet in wait list queue
void wait_in_queue(ARP_Buf *entry, uint8_t *packet, unsigned int length)
{
    Wait_List *new = (Wait_List *)malloc(sizeof(Wait_List));
    new->packet = (uint8_t *)malloc(length);
    new->len = length;
    memcpy(new->packet, packet, length);

    Wait_List *t = entry->head.next;
    entry->head.next = new;
    new->next = t;
}

// remove the packet from wait list queue
uint8_t *remove_from_queue(ARP_Buf *entry, unsigned int *length)
{
    Wait_List *t = entry->head.next;
    
    if (t == NULL)
        return NULL;

    uint8_t *packet = t->packet;
    *length = t->len;
    entry->head.next = t->next;
    free(t);
    return packet;
}
