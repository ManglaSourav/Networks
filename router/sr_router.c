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

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "Packet_Helper.h"

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
    icmp_h->checksum = icmp_cksum((uint16_t *)icmp_h, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip));
    icmp_h->type = ICMP_REP;                     // make type to ICP reply
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
    // PERFORMING CHECKS END ****************************************

    // if we find that the packet is addressed to the router itself, we
    // attempt to deal with it if it's a ping.
    struct sr_if *if_walker = 0;
    if_walker = sr->if_list;

    while (if_walker)
    {
        DebugMAC(if_walker->addr);
        if (if_walker->ip == ip_dest)
        {
            handle_icmp_pack(sr, packet, len, interface);
            return;
        }
        if_walker = if_walker->next;
    }

    // TRAVERSE ROUTING TABLE FOR IP START **************************
    // we look for the interface that corresponds to the destination
    // IP (ignoring the default route). If there are no matching
    // interfaces, we then use the default route to send the packet
    // to the gateway.

    struct sr_rt *rt_walker = NULL, *default_route = NULL;
    if (sr->routing_table == 0)
    {
        printf(" *warning* Routing table empty \n");
        return;
    }

    rt_walker = sr->routing_table;
    while (rt_walker)
    {
        if (rt_walker->dest.s_addr == 0)
        {
            default_route = rt_walker;
        }
        else if ((ip_dest & rt_walker->mask.s_addr) == (rt_walker->dest.s_addr & rt_walker->mask.s_addr))
        {
            break;
        }
        rt_walker = rt_walker->next;
    }

    if (rt_walker == NULL && default_route != NULL)
    {
        rt_walker = default_route;
        // we look to send to the gateway instead
        ip_dest = rt_walker->gw.s_addr;
        flag_def = 1;
    }
    // TRAVERSE ROUTING TABLE FOR IP END ****************************

    // TRAVERSE ARP CACHE TABLE FOR IP START **************************
    ARP_Cache *cache_temp = &arp_head;
    while (cache_temp != NULL)
    {
        unsigned char *haddr = checkExists(cache_temp, ip_dest);
        if (haddr != NULL)
        {
            --ip_part->ip_ttl;

            ip_part->ip_sum = 0;
            temp = cksum((void *)ip_part, ip_part->ip_hl * 4 / 2);
            ip_part->ip_sum = temp;

            // not necessary to check again, but just in case
            temp = cksum((void *)ip_part, ip_part->ip_hl * 4 / 2);
            if (temp != 0)
                return;

            // modify the ethernet header,
            struct sr_if *interface_info = sr_get_interface(sr, rt_walker->interface);
            memcpy(eth_hdr->ether_shost, interface_info->addr, sizeof(eth_hdr->ether_shost));
            memcpy(eth_hdr->ether_dhost, haddr, sizeof(eth_hdr->ether_dhost));

            // then send off the packet.
            int rc = sr_send_packet(sr, packet, len, rt_walker->interface);
            assert(rc == 0);
            return;
        }
        cache_temp = cache_temp->next;
    }

    // if no ARP cache entry exists,
    if (cache_temp == NULL)
    {
        // we see if we are still waiting on an ARP request for that IP.
        ARP_Buf *check_buf = checkExistsBuf(&buf_head, ip_dest);

        // if we are not waiting, we send out an ARP request.
        if (check_buf == NULL)
        {
            check_buf = insertNewEntry(&buf_head, ip_dest);
            queueWaiting(check_buf, packet, len);
            if (flag_def)
            {
                send_arp_req(sr, packet, rt_walker->interface, ip_dest);
            }
            else
            {
                send_arp_req(sr, packet, rt_walker->interface, 0);
            }
            // otherwise, we queue the packet to wait for that ARP response.
        }
        else
        {
            queueWaiting(check_buf, packet, len);
        }
    }
    // TRAVERSE ARP CACHE TABLE FOR IP START **************************
}

/*---------------------------------------------------------------------
 * Method: send_arp_req(struct sr_instance* sr,
 *                     uint8_t * orig_packet,
 *                     char* interface)
 *
 *This method is called when an ARP request needs to be sent to
 *discover the hardware address of a specific IP. It creates a packet
 *with just enough size for the ethernet and arp header, modifies them
 *accordingly, and then sends an ARP request to the interface specified
 *via the interface parameter.
 *NOTE: The dest_ip parameter is 0 for normal queries, but for queries
 *where the IPs do not match with any of the interfaces aka the default
 *route is selected, the dest_ip is set to the IP of the gateway.
 *---------------------------------------------------------------------*/
void send_arp_req(struct sr_instance *sr,
                  uint8_t *orig_packet,
                  char *interface,
                  uint32_t dest_ip)
{
    uint8_t packet[sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr)];
    memset(&packet, 0, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr));
    struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr *)packet;
    struct sr_arphdr *arp = (struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr));

    // REQUIRED VALUES BEGIN ****************************************
    // make destination MAC bits all 1
    for (int i = 0; i < ETHER_ADDR_LEN; ++i)
    {
        eth->ether_dhost[i] = ~(eth->ether_dhost[i] & 0);
    }
    eth->ether_type = ntohs(ETHERTYPE_ARP);
    arp->ar_hrd = ntohs(ARPHDR_ETHER);
    arp->ar_pro = ntohs(ETHERTYPE_IP);
    arp->ar_hln = 6;
    arp->ar_pln = 4;
    arp->ar_op = ntohs(ARP_REQUEST);
    // REQUIRED VALUES END ******************************************

    // need to test to see if I can shorten this via
    // if_walker = sr_get_interface(sr, interface)
    struct sr_if *if_walker = 0;
    if_walker = sr->if_list;
    while (if_walker)
    {
        if (strncmp(interface, if_walker->name, sizeof(if_walker->name)) == 0)
            break;

        if_walker = if_walker->next;
    }

    memcpy(eth->ether_shost, if_walker->addr, sizeof(eth->ether_shost));
    arp->ar_sip = if_walker->ip;

    memcpy(arp->ar_sha, eth->ether_shost, sizeof(arp->ar_sha));

    // if we are not sending it via the default route,
    if (dest_ip == 0)
    {
        arp->ar_tip = ((struct ip *)(orig_packet + sizeof(struct sr_ethernet_hdr)))->ip_dst.s_addr;
    }
    else
    { // otherwise we send it to the gateway.
        arp->ar_tip = dest_ip;
    }
    memset(arp->ar_tha, 0, sizeof(arp->ar_tha));

    int rc = sr_send_packet(sr, packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr), interface);
    assert(rc == 0);
}

/*---------------------------------------------------------------------
 * Method: void sr_handle_arp_pack(struct sr_instance* sr,
 *                           uint8_t * packet,
 *                           unsigned int len,
 *                           char* interface)
 *
 *This method is called when an ARP request needs to be sent to
 *discover the hardware address of a specific IP.
 *It also deals with ARP replies by sending all packets delayed
 *because we were waiting for an ARP response.
 *---------------------------------------------------------------------*/
void sr_handle_arp_pack(struct sr_instance *sr,
                        uint8_t *packet,
                        unsigned int len,
                        char *interface)
{
    struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr *)packet;
    struct sr_arphdr *arp = (struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr));

    // if we have an ARP request,
    if (arp->ar_op == ntohs(1))
    {
        // we attempt to find the interface
        struct sr_if *if_walker = 0;
        if (sr->if_list == 0)
        {
            printf(" Interface list empty \n");
            return;
        }
        if_walker = sr->if_list;
        while (if_walker != NULL)
        {
            struct in_addr ip_addr, ip_addr1;
            ip_addr.s_addr = arp->ar_tip;
            ip_addr1.s_addr = if_walker->ip;

            // if we find the interface,
            if (if_walker->ip == arp->ar_tip)
            {
                arp->ar_op = ntohs(2);
                memcpy(arp->ar_tha, arp->ar_sha, sizeof(arp->ar_tha));
                memcpy(arp->ar_sha, if_walker->addr, sizeof(arp->ar_sha));
                uint32_t temp = arp->ar_tip;
                arp->ar_tip = arp->ar_sip;
                arp->ar_sip = temp;

                memcpy(eth->ether_dhost, eth->ether_shost, sizeof(eth->ether_dhost));
                memcpy(eth->ether_shost, arp->ar_sha, sizeof(arp->ar_sha));

                int rc = sr_send_packet(sr, packet, len, interface);
                assert(rc == 0);
                break;
            }
            if_walker = if_walker->next;
        }

        // this should never happen
        if (if_walker->next == NULL)
        {
            printf("we have reached the end of the road");
        }
    }
    else if (arp->ar_op == ntohs(2))
    {
        // otherwise if we have an ARP response, we parse it if we are waiting for a response
        ARP_Buf *curr = checkExistsBuf(&buf_head, arp->ar_sip);

        // if we got a response but never sent a request, ignore it
        if (curr == NULL)
            return;

        // otherwise, we add the info to our ARP cache
        insertEntry(&arp_head, arp->ar_sip, arp->ar_sha);
        // print_arp_cache(arp_head);
        unsigned int buf_len = 0;
        uint8_t *buf_packet = extractPacket(curr, &buf_len);
        while (buf_packet != NULL)
        {
            struct ip *ip_part = (struct ip *)(buf_packet + sizeof(struct sr_ethernet_hdr));

            sr_handlepacket(sr, buf_packet, buf_len, interface);

            free(buf_packet);
            buf_packet = extractPacket(curr, &buf_len);
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
    /* REQUIRES */
    assert(sr);

    arp_head.next = NULL;
    buf_head.next = NULL;
} /* -- sr_init -- */

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

    struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr *)packet;
    auto type = htons(eth->ether_type);
    if (type == ETHERTYPE_ARP)
    {
        sr_handle_arp_pack(sr, packet, len, interface);
    }
    else if (type == ETHERTYPE_IP)
    {
        sr_handle_ip_pack(sr, packet, len, interface);
    }
}
