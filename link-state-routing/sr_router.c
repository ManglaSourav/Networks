/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing. 11
 * 90904102
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include "Packet_Helper.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_pwospf.h"

// List header to maintain cache and buffer
ARP_Cache arp_head;
ARP_Buf buf_head;

/*---------------------------------------------------------------------
 * Method: handle_icmp_pack(struct sr_instance* sr,
 *                     uint8_t * packet,
 *                     unsigned int len,
 *                     char* interface)
 *
 *When the packet arrives at the IP layer, this function is invoked.
 *The packet is initially examined to see whether it is an ICMP request;
 *if so, the checksum is used to confirm the validity of the packet.
 *The packet that the router will then change and send back to the sender
 *as a response is then modified. We discard the packet at any place
 *where a requirement is not satisfied.
 *---------------------------------------------------------------------*/
void handle_icmp_pack(struct sr_instance *sr,
                      uint8_t *packet,
                      unsigned int len,
                      char *interface)
{
    struct ip *ip = (struct ip *)(sizeof(struct sr_ethernet_hdr) + packet);
    if (ip->ip_p != IPPROTO_ICMP) // drop the packet if not ICMP packet
        return;

    struct icmp_hdr *icmp_h = (struct icmp_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
    if (icmp_h->type != ICMP_REQ || icmp_h->code != 0)
        return;
    uint16_t pack_checksum = icmp_h->checksum;
    icmp_h->checksum = 0;
    icmp_h->checksum = icmp_cksum((uint16_t *)icmp_h, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip)); // new checksum
    if (pack_checksum != icmp_h->checksum)
    {
        printf("Checksum do not match , %d vs %d\n", pack_checksum, icmp_h->checksum);
        return;
    }
    uint32_t t = ip->ip_src.s_addr; // Otherwise, change the IP header's source and destination
    ip->ip_src.s_addr = ip->ip_dst.s_addr;
    ip->ip_dst.s_addr = t;

    icmp_h->checksum = 0;
    icmp_h->type = ICMP_REP; // make type to ICP reply
    icmp_h->checksum = icmp_cksum((uint16_t *)icmp_h, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip));
    sr_handlepacket(sr, packet, len, interface); // in last, send out the packet.
}

/*---------------------------------------------------------------------
 * Method: sr_handle_ip_pack(struct sr_instance* sr,
 *                     uint8_t * packet,
 *                     unsigned int len,
 *                     char* interface)
 *
 *Processing IP packet
 *---------------------------------------------------------------------*/
void sr_handle_ip_pack(struct sr_instance *sr,
                       uint8_t *packet,
                       unsigned int len,
                       char *interface)
{
    struct ip *ip_part = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
    uint32_t ip_dest = ip_part->ip_dst.s_addr;
    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;
    char flag_def = 0;

    if (ip_part->ip_v != 4)
        return;
    u_short temp = cksum((void *)ip_part, ip_part->ip_hl * 2);
    if (temp != 0)
        return;
    if (ip_part->ip_ttl == 1)
        return;

    // handling ping
    struct sr_if *ping_handler = 0;
    ping_handler = sr->if_list;

    while (ping_handler)
    {
        if (ping_handler->ip == ip_dest)
        {
            handle_icmp_pack(sr, packet, len, interface);
            return;
        }
        ping_handler = ping_handler->next;
    }

    // check matching interface and forward
    struct sr_rt *route_handler = NULL;
    struct sr_rt *default_route = NULL;
    if (sr->routing_table == 0)
    {
        printf("Routing Table is empty \n");
        return;
    }
    route_handler = sr->routing_table;

    while (route_handler)
    {
        if (route_handler->dest.s_addr == 0)
            default_route = route_handler;
        else if ((ip_dest & route_handler->mask.s_addr) == (route_handler->dest.s_addr & route_handler->mask.s_addr))
            break; // break we find matching destination address
        route_handler = route_handler->next;
    }

    if (route_handler == NULL && default_route != NULL)
    {
        flag_def = 1;
        route_handler = default_route;
        ip_dest = route_handler->gw.s_addr; // send to the gateway instead
    }
    ARP_Cache *cache_t = &arp_head;
    while (cache_t != NULL)
    {
        unsigned char *mac_addr = entry_exists_in_cache(cache_t, ip_dest);
        if (mac_addr != NULL)
        {
            --ip_part->ip_ttl; // decrement the ttl by 1
            ip_part->ip_sum = 0;
            temp = cksum((void *)ip_part, ip_part->ip_hl * 2);
            ip_part->ip_sum = temp;
            temp = cksum((void *)ip_part, ip_part->ip_hl * 2);
            if (temp != 0)
                return;
            // swapping header information
            struct sr_if *if_info = sr_get_interface(sr, route_handler->interface);
            memcpy(eth_hdr->ether_shost, if_info->addr, sizeof(eth_hdr->ether_shost));
            memcpy(eth_hdr->ether_dhost, mac_addr, sizeof(eth_hdr->ether_dhost));
            sr_send_packet(sr, packet, len, route_handler->interface); // send the packet
            return;
        }
        cache_t = cache_t->next;
    }

    if (cache_t == NULL)
    {

        ARP_Buf *buffer = entry_exists_in_buf(&buf_head, ip_dest);
        if (buffer == NULL)
        {
            buffer = insert_ARPBuf_Entry(&buf_head, ip_dest);
            wait_in_queue(buffer, packet, len);
            if (flag_def)
                send_arp_req(sr, packet, route_handler->interface, ip_dest);
            else
                send_arp_req(sr, packet, route_handler->interface, 0);
        }
        else
            wait_in_queue(buffer, packet, len);
    }
}

/*---------------------------------------------------------------------
 * Method: send_arp_req(struct sr_instance* sr,
 *                     uint8_t *packet,
 *                     char* interface)
 *
 *This method sends the ARP request
 *---------------------------------------------------------------------*/
void send_arp_req(struct sr_instance *sr,
                  uint8_t *packet,
                  char *interface,
                  uint32_t dest_ip)
{
    int size_temp = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr);
    uint8_t temp_packet[size_temp];
    memset(&temp_packet, 0, size_temp);
    struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr *)temp_packet;
    struct sr_arphdr *arp = (struct sr_arphdr *)(temp_packet + sizeof(struct sr_ethernet_hdr));

    for (int i = 0; i < ETHER_ADDR_LEN; ++i)
        eth->ether_dhost[i] = ~(eth->ether_dhost[i] & 0);
    arp->ar_hln = 6;
    arp->ar_pln = 4;
    eth->ether_type = ntohs(ETHERTYPE_ARP);
    arp->ar_hrd = ntohs(ARPHDR_ETHER);
    arp->ar_pro = ntohs(ETHERTYPE_IP);
    arp->ar_op = ntohs(ARP_REQUEST);

    struct sr_if *if_handler = 0;
    if_handler = sr->if_list;
    while (if_handler)
    {
        if (strncmp(interface, if_handler->name, sizeof(if_handler->name)) == 0)
            break;
        if_handler = if_handler->next;
    }

    memcpy(eth->ether_shost, if_handler->addr, sizeof(eth->ether_shost));
    arp->ar_sip = if_handler->ip;
    memcpy(arp->ar_sha, eth->ether_shost, sizeof(arp->ar_sha));

    if (dest_ip == 0)
        arp->ar_tip = ((struct ip *)(packet + sizeof(struct sr_ethernet_hdr)))->ip_dst.s_addr;
    else
        arp->ar_tip = dest_ip;

    memset(arp->ar_tha, 0, sizeof(arp->ar_tha));
    sr_send_packet(sr, temp_packet, size_temp, interface);
}

/*---------------------------------------------------------------------
 * Method: void sr_handle_arp_pack(struct sr_instance* sr,
 *                           uint8_t *packet,
 *                           unsigned int len,
 *                           char* interface)
 *
 *This method handle arp responses
 *---------------------------------------------------------------------*/
void sr_handle_arp_pack(struct sr_instance *sr,
                        uint8_t *packet,
                        unsigned int len,
                        char *interface)
{
    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;
    struct sr_arphdr *arp_hdr = (struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr));

    if (arp_hdr->ar_op == ntohs(1))
    {
        struct sr_if *if_handler = 0;
        if (sr->if_list == 0)
        {
            printf("No Interfacesf ound \n");
            return;
        }
        if_handler = sr->if_list;
        while (if_handler != NULL)
        {
            if (if_handler->ip == arp_hdr->ar_tip)
            {
                arp_hdr->ar_op = ntohs(2);
                memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, sizeof(arp_hdr->ar_tha));
                memcpy(arp_hdr->ar_sha, if_handler->addr, sizeof(arp_hdr->ar_sha));
                uint32_t t = arp_hdr->ar_tip;
                arp_hdr->ar_tip = arp_hdr->ar_sip;
                arp_hdr->ar_sip = t;
                memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
                memcpy(eth_hdr->ether_shost, arp_hdr->ar_sha, sizeof(arp_hdr->ar_sha));
                sr_send_packet(sr, packet, len, interface);
                break;
            }
            if_handler = if_handler->next;
        }
        if (if_handler->next == NULL)
            printf("Found Error");
    }
    else if (arp_hdr->ar_op == ntohs(2))
    {
        ARP_Buf *curr = entry_exists_in_buf(&buf_head, arp_hdr->ar_sip);
        if (curr == NULL)
            return;
        insert_ARPCache_Entry(&arp_head, arp_hdr->ar_sip, arp_hdr->ar_sha);
        unsigned int buf_length = 0;
        uint8_t *buf_packet = remove_from_queue(curr, &buf_length);
        while (buf_packet != NULL)
        {
            sr_handlepacket(sr, buf_packet, buf_length, interface);
            free(buf_packet);
            buf_packet = remove_from_queue(curr, &buf_length);
        }
    }
}

/*---------------------------------------------------------------------
 * Method: sr_init(struct sr_instance* sr)
 * Scope:  Global
 *
 * Initialize ARP cache and buffer used for packets waiting on ARP
 * responses.
 *---------------------------------------------------------------------*/
void sr_init(struct sr_instance *sr)
{
    assert(sr);

    arp_head.next = NULL;
    buf_head.next = NULL;
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(struct sr_instance* sr,
 *                         uint8_t * packet,
 *                         unsigned int len,
 *                         char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface. The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *---------------------------------------------------------------------*/
void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
    assert(sr);
    assert(packet);
    assert(interface);
    printf("Recived packet of len %d on %s\n", len, interface);

    struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr *)packet;
    int type = htons(eth->ether_type);
    if (type == ETHERTYPE_IP)
        sr_handle_ip_pack(sr, packet, len, interface);
    else if (type == ETHERTYPE_ARP)
        sr_handle_arp_pack(sr, packet, len, interface);
}
