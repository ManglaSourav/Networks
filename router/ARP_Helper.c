#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "sr_router.h"
#include "ARP_Helper.h"

// inserts ARP entry at beginning of linked list
void insertEntry(ARP_Cache *head, uint32_t ip, unsigned char *addr)
{
    ARP_Cache *new = (ARP_Cache *)malloc(sizeof(ARP_Cache));
    new->ip = ip;
    memcpy(new->addr, addr, sizeof(new->addr));

    ARP_Cache *temp = head->next;
    head->next = new;
    new->next = temp;
}

// returns 1 if exists, 0 if does not. If exists, fill out addr.
unsigned char *checkExists(ARP_Cache *head, uint32_t ip)
{
    ARP_Cache *curr = head;
    while (curr->next != NULL && (curr->next)->ip != ip)
    {
        curr = curr->next;
    }

    if (curr->next != NULL)
    {
        // DebugMAC("%d ", curr->next->ip);
        return curr->next->addr; // we found it.
    }

    return NULL;
}

// returns the node if exists, NULL if does not
ARP_Buf *checkExistsBuf(ARP_Buf *head, uint32_t ip)
{
    ARP_Buf *curr = head;
    while (curr->next != NULL && (curr->next)->ip != ip)
    {
        curr = curr->next;
    }

    if (curr->next != NULL)
    {
        return curr->next; // we found it.
    }

    return NULL;
}

void deleteIP(ARP_Buf *head, uint32_t ip);

// inserts process at beginning of linked list
ARP_Buf *insertNewEntry(ARP_Buf *head, uint32_t ip)
{
    ARP_Buf *new = (ARP_Buf *)malloc(sizeof(ARP_Buf));
    new->ip = ip;
    new->head.next = NULL;

    ARP_Buf *temp = head->next;
    head->next = new;
    new->next = temp;

    return new;
}

void queueWaiting(ARP_Buf *spot, uint8_t *packet, unsigned int len)
{
    Wait_List *new = (Wait_List *)malloc(sizeof(Wait_List));
    new->packet = (uint8_t *)malloc(len);
    memcpy(new->packet, packet, len);
    new->len = len;

    Wait_List *temp = spot->head.next;
    spot->head.next = new;
    new->next = temp;
}

// It is the responsibility of the caller to free the packet after processing.
uint8_t *extractPacket(ARP_Buf *spot, unsigned int *len)
{
    Wait_List *temp = spot->head.next;
    if (temp == NULL)
    {
        return NULL;
    }
    uint8_t *packet = temp->packet;
    *len = temp->len;

    spot->head.next = temp->next;
    free(temp);

    return packet;
}
