/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 * 90904102
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "top_db.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_pwospf.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "pwospf_protocol.h"
#include "Packet_Helper.h"

void handle_pwospf(struct sr_instance *sr,
                   uint8_t *packet,
                   unsigned int len,
                   char *interface)
{
    // struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr*) packet;
    // struct ip *ip = (struct ip*) (packet + sizeof(struct sr_ethernet_hdr));
    struct ospfv2_hdr *ospf_hdr = (struct ospfv2_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));

    if (ospf_hdr->type == OSPF_TYPE_HELLO)
    {
        // struct ospfv2_hello_hdr *hello_hdr = (struct ospfv2_hello_hdr*) (ospf_hdr + sizeof(struct ospfv2_hdr));
        // if(address is broadcast)
        // if(checksum valid)
        //  for now, ignore checks
        //  if we have a pwospf hello packet, check if 224.0.0.5

        pwospf_lock(sr->ospf_subsys);
        handle_pwospf_hello(sr, packet, len, interface);
        pwospf_unlock(sr->ospf_subsys);
    }
    else if (ospf_hdr->type == OSPF_TYPE_LSU)
    {
        pwospf_lock(sr->ospf_subsys);
        if (handle_pwospf_lsu(sr, packet, len, interface))
        {
            send_updates(sr); // change in topology to send update
        }
        pwospf_unlock(sr->ospf_subsys);
    }
}

char handle_pwospf_lsu(struct sr_instance *sr,
                       uint8_t *packet,
                       unsigned int len,
                       char *interface)
{
    struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr *)packet;
    struct ip *ip = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
    struct ospfv2_hdr *ospf_hdr = (struct ospfv2_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));

    // lsu specific headers
    struct ospfv2_lsu_hdr *lsu_hdr = (struct ospfv2_lsu_hdr *)((uint8_t *)ospf_hdr + sizeof(struct ospfv2_hdr));
    struct ospfv2_lsu *lsu_ad = (struct ospfv2_lsu *)((uint8_t *)lsu_hdr + sizeof(struct ospfv2_lsu_hdr));

    int i;
    for (i = 0; i < ETHER_ADDR_LEN; ++i)
    {
        if (eth->ether_dhost[i] != 0)
            break;
    }
    // this means we sent an ARP request and need to resend the packet.
    if (i == ETHER_ADDR_LEN)
    {
        ARP_Cache *cache_temp = &(sr->arp_head);
        unsigned char *haddr = entry_exists_in_cache(cache_temp, ip->ip_dst.s_addr);
        if (haddr != NULL)
        {
            memcpy(eth->ether_dhost, haddr, sizeof(eth->ether_dhost));
            int rc = sr_send_packet(sr, packet, len, interface);
            assert(rc == 0);
        }
        else
        {
            struct in_addr ip_dest;
            ip_dest.s_addr = ip->ip_dst.s_addr;
            printf("NO ARP CACHE ENTRY EXISTS FOR IP %s, SHOULD NOT HAPPEN.\n", inet_ntoa(ip_dest));
        }
        return 0;
    }

    // otherwise, we process the packet normally
    Router *router = &(sr->ospf_subsys->head_router);
    // printf("Router info: %d\n", router->next->seq);
    router = checkRouterExists(router, ospf_hdr->rid);
    char flag = 0;

    if (sr_get_interface(sr, "eth0")->ip == ospf_hdr->rid)
    {
        return flag;
    }

    // if router does not exist, add it
    if (router == NULL)
    {
        // print("Adding new router in update\n");
        router = insertNewRouter(&(sr->ospf_subsys->head_router), ospf_hdr->rid);
        struct sr_if *iface = sr_get_interface(sr, interface);
        iface->neighbor_ip = ip->ip_src.s_addr;
        iface->neighbor_rid = ospf_hdr->rid;
        iface->up = 1;
        // sr_print_if(iface);

        // then, we update the next hops if they exists
        struct sr_rt *rt_walker = sr->routing_table;
        while (rt_walker)
        {
            if (strcmp(rt_walker->interface, iface->name) == 0)
                rt_walker->gw.s_addr = iface->neighbor_ip;
            rt_walker = rt_walker->next;
        }
        flag = 1;
    }

    if (lsu_hdr->seq <= router->seq)
    {
        return flag;
    }

    removeAllLinks(router);
    for (i = 0; i < lsu_hdr->num_adv; ++i)
    {
        if (lsu_ad->rid == 0)
            addLink(router, lsu_ad->subnet, lsu_ad->mask, ospf_hdr->rid);
        else
            addLink(router, lsu_ad->subnet, lsu_ad->mask, lsu_ad->rid);

        lsu_ad = (struct ospfv2_lsu *)((uint8_t *)lsu_ad + sizeof(struct ospfv2_lsu));
    }

    recalculate_rt(sr);

    return flag;
}

/*---------------------------------------------------------------------
 * Method: handle_pwospf_hello(struct sr_instance* sr,
 *                             uint8_t * packet,
 *                             unsigned int len,
 *                             char* interface)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/
void handle_pwospf_hello(struct sr_instance *sr,
                         uint8_t *packet,
                         unsigned int len,
                         char *interface)
{
    struct ip *ip = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
    struct ospfv2_hdr *ospf_hdr = (struct ospfv2_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));

    Router *router = &(sr->ospf_subsys->head_router);
    router = checkRouterExists(router, ospf_hdr->rid);

    // if we found a new router,
    if (router == NULL)
    {
        // printf("Inserting new router.\n");
        router = insertNewRouter(&(sr->ospf_subsys->head_router), ospf_hdr->rid);

        struct sr_if *iface = sr_get_interface(sr, interface);
        iface->neighbor_ip = ip->ip_src.s_addr;
        iface->neighbor_rid = ospf_hdr->rid;
        iface->up = 1;
        // sr_print_if(iface);

        // then, we update the next hop if it exists
        struct sr_rt *rt_walker = sr->routing_table;
        while (rt_walker)
        {
            if (strcmp(rt_walker->interface, iface->name) == 0)
            {
                // print("Replacing nexthop\n");
                rt_walker->gw.s_addr = iface->neighbor_ip;
            }
            rt_walker = rt_walker->next;
        }
        send_updates(sr); // change in topology to send update
    }
    else
    {
        updateTime(router);
    }

    // print_db(&(sr->ospf_subsys->head_router));
    // printf("*****\n");
}

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr)
{
    assert(sr);

    sr->arp_head.next = NULL;
    sr->buf_head.next = NULL;
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
    printf("Recived packet of len %d on %s\n", len, interface);

    struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr *)packet;
    int type = htons(eth->ether_type);
    if (type == ETHERTYPE_IP)
        sr_handle_ip_pack(sr, packet, len, interface);
    else if (type == ETHERTYPE_ARP)
        sr_handle_arp_pack(sr, packet, len, interface);
        
} /* end sr_ForwardPacket */

/*---------------------------------------------------------------------
 *Method: handle_icmp_pack(struct sr_instance* sr,
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
 *This method is called when the packet received by the router is
 *identified to have a type of IP.
 *---------------------------------------------------------------------*/
void sr_handle_ip_pack(struct sr_instance *sr, // TODO: modify this
                       uint8_t *packet,
                       unsigned int len,
                       char *interface)
{
    struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr *)packet;
    struct ip *ip_portion = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));

    uint32_t dest_ip = ip_portion->ip_dst.s_addr;
    char take_default = 0;

    // PERFORMING CHECKS START **************************************
    if (ip_portion->ip_v != 4)
        return;
    u_short test = cksum((void *)ip_portion, ip_portion->ip_hl * 4 / 2);
    if (test != 0)
        return;
    if (ip_portion->ip_ttl == 1)
        return;
    // PERFORMING CHECKS END ****************************************

    if (ip_portion->ip_p == IPROTO_OSPF)
    {
        handle_pwospf(sr, packet, len, interface);
        return;
    }

    // if we find that the packet is addressed to the router itself, we
    // attempt to deal with it if it's a ping.
    struct sr_if *if_walker = 0;
    if_walker = sr->if_list;

    struct in_addr temp_addr;
    while (if_walker != NULL)
    {
        if (if_walker->ip == dest_ip)
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

    pwospf_lock(sr->ospf_subsys);
    struct sr_rt *rt_walker = NULL, *default_route = NULL, *match = NULL;
    if (sr->routing_table == 0)
    {
        pwospf_unlock(sr->ospf_subsys);
        return;
    }

    rt_walker = sr->routing_table;
    while (rt_walker)
    {
        if (rt_walker->dest.s_addr == 0)
        {
            default_route = rt_walker;
        }
        else if ((dest_ip & rt_walker->mask.s_addr) == (rt_walker->dest.s_addr & rt_walker->mask.s_addr))
        {
            if (match == NULL || rt_walker->mask.s_addr > match->mask.s_addr)
            {
                match = rt_walker;
            }
        }
        rt_walker = rt_walker->next;
    }
    pwospf_unlock(sr->ospf_subsys);

    // there should never be a case where the default route is NULL
    if (match == NULL && default_route != NULL)
    {
        match = default_route;
        // we look to send to the gateway instead
        dest_ip = match->gw.s_addr;
        take_default = 1;
    }
    else if (match == NULL)
    {
        // printf("No route to get there.\n");
        return;
    }
    else if (match->gw.s_addr != 0)
    {
        dest_ip = match->gw.s_addr;
    }
    // TRAVERSE ROUTING TABLE FOR IP END ****************************

    // TRAVERSE ARP CACHE TABLE FOR IP START **************************
    ARP_Cache *cache_temp = &(sr->arp_head);
    while (cache_temp != NULL)
    {
        unsigned char *haddr = entry_exists_in_cache(cache_temp, dest_ip);
        if (haddr != NULL)
        {
            --ip_portion->ip_ttl;

            ip_portion->ip_sum = 0;
            test = cksum((void *)ip_portion, ip_portion->ip_hl * 4 / 2);
            ip_portion->ip_sum = test;

            // not necessary to check again, but just in case
            test = cksum((void *)ip_portion, ip_portion->ip_hl * 4 / 2);
            if (test != 0)
                return;

            // modify the ethernet header,
            struct sr_if *interface_info = sr_get_interface(sr, match->interface);
            memcpy(eth->ether_shost, interface_info->addr, sizeof(eth->ether_shost));
            memcpy(eth->ether_dhost, haddr, sizeof(eth->ether_dhost));

            // then send off the packet.
            int rc = sr_send_packet(sr, packet, len, match->interface);
            assert(rc == 0);
            return;
        }
        cache_temp = cache_temp->next;
    }

    // if no ARP cache entry exists,
    if (cache_temp == NULL)
    {

        // we see if we are still waiting on an ARP request for that IP.
        ARP_Buf *check_buf = entry_exists_in_buf(&(sr->buf_head), dest_ip);

        // if we are not waiting, we send out an ARP request.
        if (check_buf == NULL)
        {

            check_buf = insert_ARPBuf_Entry(&(sr->buf_head), dest_ip);
            wait_in_queue(check_buf, packet, len);

            // need to adjust to send for when gateway != 0
            if (take_default || match->gw.s_addr != 0)
            {
                send_arp_req(sr, packet, match->interface, dest_ip);
            }
            else
            {
                send_arp_req(sr, packet, match->interface, 0);
            }
            // otherwise, we queue the packet to wait for that ARP response.
        }
        else
        {
            wait_in_queue(check_buf, packet, len);
        }
    }
    // TRAVERSE ARP CACHE TABLE FOR IP START **************************
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
 *                           uint8_t * packet,
 *                           unsigned int len,
 *                           char* interface)
 *
 *This method is called when an ARP request needs to be sent to
 *discover the hardware address of a specific IP.
 *It also deals with ARP replies by sending all packets delayed
 *because we were waiting for an ARP response.
 *---------------------------------------------------------------------*/
void sr_handle_arp_pack(struct sr_instance *sr, // TODO: modify this
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
            // printf(" Interface list empty \n");
            return;
        }
        if_walker = sr->if_list;
        while (if_walker != NULL)
        {
            // struct in_addr ip_addr; , ip_addr1;
            // ip_addr.s_addr = arp->ar_tip;
            // ip_addr1.s_addr = if_walker->ip;

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
            struct in_addr temp;
            temp.s_addr = arp->ar_sip;
            // printf("ARP Req from %s\n", inet_ntoa(temp));
            temp.s_addr = arp->ar_tip;
            // printf("ARP Req for %s yielded no matches\n", inet_ntoa(temp));
        }
    }
    else if (arp->ar_op == ntohs(2))
    {
        // otherwise if we have an ARP response, we parse it if we are waiting for a response
        ARP_Buf *curr = entry_exists_in_buf(&(sr->buf_head), arp->ar_sip);

        // if we got a response but never sent a request, ignore it
        if (curr == NULL)
            return;

        // otherwise, we add the info to our ARP cache
        insert_ARPCache_Entry(&(sr->arp_head), arp->ar_sip, arp->ar_sha);
        // print_arp_cache((sr->arp_head));
        unsigned int buf_len = 0;
        uint8_t *buf_packet = extractPacket(curr, &buf_len);
        while (buf_packet != NULL)
        {
            // struct ip *ip_portion = (struct ip*) (buf_packet + sizeof(struct sr_ethernet_hdr));
            sr_handlepacket(sr, buf_packet, buf_len, interface);

            free(buf_packet);
            buf_packet = extractPacket(curr, &buf_len);
        }
    }
}
