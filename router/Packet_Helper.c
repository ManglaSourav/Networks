#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "sr_router.h"
#include "Packet_Helper.h"

// insert new cache entry
void insert_ARPCache_Entry(ARP_Cache *head, uint32_t ip, unsigned char *addr)
{
    ARP_Cache *temp = (ARP_Cache *)malloc(sizeof(ARP_Cache));
    temp->ip = ip;
    memcpy(temp->addr, addr, sizeof(temp->addr));
    ARP_Cache *t = head->next;
    head->next = temp;
    temp->next = t;
}

// check entry present in the cache or not
unsigned char *entry_exists_in_cache(ARP_Cache *head, uint32_t ip)
{
    ARP_Cache *temp = head;
    while (temp->next != NULL && (temp->next)->ip != ip)
        temp = temp->next;
    if (temp->next != NULL)
        return temp->next->addr;
    return NULL;
}

// icmp checksum
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

// simple checksum from handout
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

// check entry is present in the buffer or not
ARP_Buf *entry_exists_in_buf(ARP_Buf *head, uint32_t ip)
{
    ARP_Buf *temp = head;
    while (temp->next != NULL && (temp->next)->ip != ip)
        temp = temp->next;
    if (temp->next != NULL)
        return temp->next;
    return NULL;
}

// insert new entry to buffer
ARP_Buf *insert_ARPBuf_Entry(ARP_Buf *head, uint32_t ip)
{
    ARP_Buf *temp = (ARP_Buf *)malloc(sizeof(ARP_Buf));
    temp->ip = ip;
    temp->head.next = NULL;
    ARP_Buf *t = head->next;
    head->next = temp;
    temp->next = t;
    return temp;
}

// put incoming packet in queue
void wait_in_queue(ARP_Buf *entry, uint8_t *packet, unsigned int length)
{
    Wait_List *temp = (Wait_List *)malloc(sizeof(Wait_List));
    temp->packet = (uint8_t *)malloc(length);
    memcpy(temp->packet, packet, length);
    temp->len = length;

    Wait_List *t = entry->head.next;
    entry->head.next = temp;
    temp->next = t;
}

// remove packet from queue
uint8_t *remove_from_queue(ARP_Buf *entry, unsigned int *len)
{
    Wait_List *temp = entry->head.next;
    if (temp == NULL)
        return NULL;
    uint8_t *packet = temp->packet;
    *len = temp->len;
    entry->head.next = temp->next;
    free(temp);
    return packet;
}
