#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_protocol.h"
#include "ARP_Helper.h"
#include "sr_router.h"
#include "sr_helpers.h"

// HELPER FUNCTIONS
//
uint16_t icmp_checksum(uint16_t *addr, int count){
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

// function taken from provided webpage
u_short cksum(u_short *buf, int count)
{
    register u_long sum = 0;

    while (count--)
    {
        sum += *buf++;
        if (sum & 0xFFFF0000)
        {
            /* carry occurred, so wrap around */
            sum &= 0xFFFF;
            sum++;
        }
    }
    return ~(sum & 0xFFFF);
}

// DEBUG FUNCTIONS
void print_icmp_header(struct icmp_hdr *icmp)
{
    printf("Type, code: %d %d\n", icmp->type, icmp->code);
}

void print_arp_cache(ARP_Cache arp_head)
{
    ARP_Cache *curr = arp_head.next;
    struct in_addr ip_addr;

    printf("----- Printing ARP cache: -----\n");
    while (curr != NULL)
    {
        ip_addr.s_addr = curr->ip;
        printf("IP: %s, MAC address: ", inet_ntoa(ip_addr));
        DebugMAC(curr->addr);
        printf("\n");
        curr = curr->next;
    }
    printf("----- Printed ARP Cache.  -----\n");
}

void print_ip_header(struct ip *ip)
{
    printf("Source ip address: %s\n", inet_ntoa(ip->ip_src));
    printf("Destination ip address: %s\n", inet_ntoa(ip->ip_dst));
}

void print_arp_header(struct sr_arphdr *arp)
{
    printf("Printing arp header:\n");
    printf("Hardware address format: %d\n", arp->ar_hrd);
    printf("Protocol address: % d\n", arp->ar_pro);
    printf("Length of hardware address: %d\n", arp->ar_hln);
    printf("Length of protocol address: %d\n", arp->ar_pln);
    printf("Opcode: %d\n", htons(arp->ar_op));
    printf("Sender hardware address: "); //\n", arp->ar_sha);
    DebugMAC(arp->ar_sha);
    printf("\n");

    struct in_addr ip_addr;
    ip_addr.s_addr = arp->ar_sip;
    printf("Sender ip addr %s\n", inet_ntoa(ip_addr));
    printf("Target hardware address: "); //\n", arp->ar_sha);
    DebugMAC(arp->ar_tha);
    printf("\n");
    ip_addr.s_addr = arp->ar_tip;
    printf("Target ip addr %s\n", inet_ntoa(ip_addr));
    // printf("\n", arp->ar_tha);
}
