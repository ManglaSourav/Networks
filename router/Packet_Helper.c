#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "sr_router.h"
#include "Packet_Helper.h"

// inserts ARP entry at beginning of linked list
void entry_exists_in_cache(ARP_Cache *head, uint32_t ip, unsigned char *addr)
{
    ARP_Cache *new = (ARP_Cache *)malloc(sizeof(ARP_Cache));
    new->ip = ip;
    memcpy(new->addr, addr, sizeof(new->addr));

    ARP_Cache *temp = head->next;
    head->next = new;
    new->next = temp;
}

// returns 1 if exists, 0 if does not. If exists, fill out addr.
unsigned char *insert_ARPCache_Entry(ARP_Cache *head, uint32_t ip)
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

uint16_t icmp_cksum(uint16_t *addr, int count)
{
    register uint32_t sum = 0;

    while (count > 1)
    {
        sum += *addr++;
        count -= 2;
    }
    if (count > 0)
        sum += *((uint8_t *)addr);
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (~sum);
}

u_short cksum(u_short *buf, int count)
{
    register u_long sum = 0;

    while (count--)
    {
        sum += *buf++;
        if (sum & 0xFFFF0000)
        {
            sum &= 0xFFFF;
            sum++;
        }
    }
    return ~(sum & 0xFFFF);
}

// returns the node if exists, NULL if does not
ARP_Buf *entry_exists_in_buf(ARP_Buf *head, uint32_t ip)
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

// inserts process at beginning of linked list
ARP_Buf *insert_ARPBuf_Entry(ARP_Buf *head, uint32_t ip)
{
    ARP_Buf *new = (ARP_Buf *)malloc(sizeof(ARP_Buf));
    new->ip = ip;
    new->head.next = NULL;

    ARP_Buf *temp = head->next;
    head->next = new;
    new->next = temp;

    return new;
}

void wait_in_queue(ARP_Buf *spot, uint8_t *packet, unsigned int len)
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
uint8_t *remove_from_queue(ARP_Buf *spot, unsigned int *len)
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
