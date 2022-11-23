/*-----------------------------------------------------------------------------
 * file: sr_pwospf.c
 * date: Tue Nov 23 23:24:18 PST 2004
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "sr_pwospf.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "pwospf_protocol.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "Packet_Helper.h"
#include "sr_router.h"

/* -- declaration of main thread function for pwospf subsystem --- */
static void *pwospf_run_thread(void *arg);

// return 0 if everything is okay, 1 otherwise
char check_timeout(struct sr_instance *sr)
{
    char flag = 0;
    Router *curr_router = &(sr->ospf_subsys->head_router);
    time_t curr_time = time(0);
    struct in_addr temp_addr;
    // printf("Checking timeout.\n");
    while (curr_router->next != NULL)
    {
        if (curr_time - curr_router->next->time >= 10)
        { // OSPF_NEIGHBOR_TIMEOUT) {
            // printf("Times: %ld %ld\n", curr_time, curr_router->next->time);
            // printf("LINK DOWN DETECTED\n");
            struct sr_if *iface = sr_get_interface_n_rid(sr, curr_router->next->rid);
            // temp.s_addr = iface->neighbor_ip;
            // printf("Interface: %s\n", iface->name);
            iface->up = 0; // mark the relevant interface as down
            iface->neighbor_ip = 0;
            iface->neighbor_rid = 0;
            // then we go through the routing table and remove entries
            struct sr_rt *curr_rt = sr->routing_table, *temp = NULL;

            while (strcmp(curr_rt->interface, iface->name) == 0 && !(curr_rt->static_flag))
            { // just in case check static
                temp_addr = curr_rt->dest;
                // printf("Removing 1st rt entry: %s\n", inet_ntoa(temp_addr));
                temp = curr_rt;
                sr->routing_table = temp->next;
                curr_rt = sr->routing_table;
                flag = 1;
                free(temp);
            }

            while (curr_rt->next != NULL)
            {
                temp_addr = curr_rt->next->dest;
                // printf("Looking at rt entry: %s, interface %s %d %d\n", inet_ntoa(temp_addr), curr_rt->next->interface, strcmp(curr_rt->next->interface, iface->name), !(curr_rt->next->static_flag));
                if (strcmp(curr_rt->next->interface, iface->name) == 0 && !(curr_rt->next->static_flag))
                {
                    temp_addr = curr_rt->next->dest;
                    // printf("Removing rt entry: %s\n", inet_ntoa(temp_addr));
                    temp = curr_rt->next;
                    curr_rt->next = temp->next;
                    free(temp);
                    flag = 1;
                }
                else
                {
                    curr_rt = curr_rt->next;
                }
            }
            delete_Router(&(sr->ospf_subsys->head_router), curr_router->next->rid);
            // print_db(&(sr->ospf_subsys->head_router));
            // sr_print_routing_table(sr);
        }
        else
        {
            curr_router = curr_router->next;
        }
    }

    return flag;
}

/*---------------------------------------------------------------------
 * Method: recalculate_rt(..)
 *
 * Sets up the internal data structures for the pwospf subsystem
 *
 * You may assume that the interfaces have been created and initialized
 * by this point.
 *---------------------------------------------------------------------*/
void recalculate_rt(struct sr_instance *sr)
{
    struct sr_if *if_walker = sr->if_list;
    struct sr_rt *rt_walker = sr->routing_table;
    // printf("********************************\n");
    // printf("RECALCULATING RT\n");
    // printf("Routers:\n");
    // print_db(&(sr->ospf_subsys->head_router));
    // printf("Initial Routing table:\n");
    // sr_print_routing_table(sr);
    // printf("\n");

    Router *router = NULL;
    while (if_walker != NULL)
    {
        if (!(if_walker->up))
        {
            if_walker = if_walker->next;
            continue;
        }

        rt_walker = sr->routing_table;
        while (rt_walker != NULL)
        {
            if ((if_walker->mask & if_walker->ip) == (rt_walker->mask.s_addr & rt_walker->dest.s_addr) && if_walker->mask > 0)
            { // aka default
                break;
            }
            rt_walker = rt_walker->next;
        }

        // if no existing route exists,
        if (rt_walker == NULL)
        {
            // we add it
            struct in_addr dest, gw, mask;
            dest.s_addr = if_walker->ip;
            gw.s_addr = if_walker->neighbor_ip;
            mask.s_addr = if_walker->mask;
            sr_add_rt_entry(sr, dest, gw, mask, if_walker->name);
            // printf("Adding to rt\n");
        }

        if_walker = if_walker->next;
    }

    // then we look at neighbors
    router = NULL;
    if_walker = sr->if_list;
    while (if_walker != NULL)
    {
        // if no neighboring router, don't look at it
        if (if_walker->neighbor_rid == 0)
        {
            // printf("Skipping interface %s\n", if_walker->name);
            if_walker = if_walker->next;
            continue;
        }
        // printf("Printing le interface info:\n");
        // sr_print_if(if_walker);

        router = check_Router_Exists(&(sr->ospf_subsys->head_router), if_walker->neighbor_rid);
        if (router == NULL)
        {
            struct in_addr temp;
            temp.s_addr = if_walker->neighbor_rid;
            // printf("For some reason router %s DNE.\n", inet_ntoa(temp));
        }
        else
        {
            struct in_addr temp_inaddr;
            temp_inaddr.s_addr = if_walker->neighbor_rid;
            // printf("***** CURRENTLY LOOKING AT ROUTER %s *****\n", inet_ntoa(temp_inaddr));
        }

        Link *curr_link = router->head.next;
        // go throughall other routers and see if they have unknown paths
        while (curr_link != NULL)
        {
            // if their route uses us, ignore
            if (curr_link->rid == sr_get_interface(sr, "eth0")->ip)
            {
                // printf("Route uses us, ignore\n");
                curr_link = curr_link->next;
                continue;
            }

            rt_walker = sr->routing_table;
            // going through all the other routes,
            while (rt_walker != NULL)
            {
                // if we find that the route already exists,
                if ((curr_link->mask & curr_link->ip) == (rt_walker->mask.s_addr & rt_walker->dest.s_addr))
                {
                    struct sr_if *temp_iface = sr_get_interface(sr, rt_walker->interface);
                    // if both routes lead to the same place, break
                    if (curr_link->rid == temp_iface->neighbor_rid)
                        break;

                    // if we have a direct route aka gateway 0, break
                    if (rt_walker->gw.s_addr == 0)
                        break;

                    // if attempting to remove static route, break
                    if (rt_walker->static_flag)
                        break;

                    // otherwise, we check to see if the route is better
                    // printf("Checking which route is superior:\n");
                    // print_link(curr_link);
                    // printf("---\n");
                    // sr_print_routing_entry(rt_walker);
                    // printf("--------\n");

                    // find interface associated with exiting route table entry
                    // sr_print_if(temp_iface);

                    Link *temp_link = search_Link(&(sr->ospf_subsys->head_router),
                                               temp_iface->neighbor_rid,
                                               rt_walker->dest.s_addr,
                                               rt_walker->mask.s_addr);

                    if (temp_link == NULL)
                        // printf("temp_link is NULL\n");

                        // if we find that things are inefficient,
                        if (temp_link->rid == curr_link->rid)
                        {
                            // printf("Replacing entry in routing table\n");
                            rt_walker->dest.s_addr = curr_link->ip;
                            rt_walker->mask.s_addr = curr_link->mask;
                            rt_walker->gw.s_addr = if_walker->neighbor_ip;
                            memcpy(rt_walker->interface, if_walker->name, sizeof(char) * SR_IFACE_NAMELEN);
                        }
                    break;
                }
                rt_walker = rt_walker->next;
            }

            // if no existing route exists,
            if (rt_walker == NULL)
            {
                // we add it
                struct in_addr dest, gw, mask;
                dest.s_addr = curr_link->ip;
                if (curr_link->mask)
                    gw.s_addr = if_walker->neighbor_ip;
                mask.s_addr = curr_link->mask;
                sr_add_rt_entry(sr, dest, gw, mask, if_walker->name);
                // printf("Adding to rt\n");
                // print_db(&(sr->ospf_subsys->head_router));
            }
            curr_link = curr_link->next;
        }

        if_walker = if_walker->next;
    }
    // printf("Finishing recalculating, new routing table:\n");
    // sr_print_routing_table(sr);
    // printf("********************************\n");
}

/*---------------------------------------------------------------------
 * Method: send_updates(struct sr_instance* sr)
 *
 *This method is called when the packet received by the router is
 *identified to have a type of IP.
 *---------------------------------------------------------------------*/
void send_updates(struct sr_instance *sr)
{
    // first, we find the number of advertisements that we need to make
    // should add all routes in routing table
    struct sr_if *if_walker = sr->if_list;
    struct sr_rt *rt_walker = sr->routing_table;
    int ad_count = 0;

    while (rt_walker != NULL)
    {
        ad_count++;
        rt_walker = rt_walker->next;
    }

    // then, we create our lsu packet,
    uint32_t lsu_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr) + (ad_count * sizeof(struct ospfv2_lsu));
    uint8_t *lsu_packet = (uint8_t *)calloc(lsu_len, sizeof(uint8_t));

    // and then begin filling out the packet
    struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr *)lsu_packet;
    eth->ether_type = ntohs(ETHERTYPE_IP);

    // INITIALIZE IP HEADER START **********
    struct ip *ip = (struct ip *)(lsu_packet + sizeof(struct sr_ethernet_hdr));
    ip->ip_v = 4;
    ip->ip_hl = 5;
    ip->ip_tos = 0; // normal
    ip->ip_len = htons(sizeof(struct ip) + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr) + ad_count * sizeof(struct ospfv2_lsu));
    ip->ip_id = 0;
    ip->ip_off = 0;
    ip->ip_ttl = 255; // max ttl put here
    ip->ip_p = IPROTO_OSPF;
    // INITIALIZE IP HEADER END   **********

    // INITIALIZE OSPF HEADER START ********
    struct ospfv2_hdr *ospf_hdr = (struct ospfv2_hdr *)((uint8_t *)ip + sizeof(struct ip));
    ospf_hdr->version = OSPF_V2;
    ospf_hdr->type = OSPF_TYPE_LSU;
    ospf_hdr->len = sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr) + ad_count * sizeof(struct ospfv2_lsu);
    ospf_hdr->rid = sr_get_interface(sr, "eth0")->ip;
    ospf_hdr->aid = 0;
    ospf_hdr->autype = 0;
    ospf_hdr->audata = 0;

    struct ospfv2_lsu_hdr *lsu_hdr = (struct ospfv2_lsu_hdr *)((uint8_t *)ospf_hdr + sizeof(struct ospfv2_hdr));
    lsu_hdr->seq = sr->ospf_subsys->curr_seq;
    sr->ospf_subsys->curr_seq++;

    lsu_hdr->ttl = 255; // arbitrary
    lsu_hdr->num_adv = ad_count;
    // INITIALIZE OSPF HEADER END   ********

    // then, we fill out the link state advertisements
    struct ospfv2_lsu *lsu_ad = (struct ospfv2_lsu *)((uint8_t *)lsu_hdr + sizeof(struct ospfv2_lsu_hdr));

    rt_walker = sr->routing_table;
    // printf("Going through ad generation:\n");
    while (rt_walker)
    {
        lsu_ad->subnet = rt_walker->dest.s_addr;
        lsu_ad->mask = rt_walker->mask.s_addr;
        lsu_ad->rid = sr_get_interface(sr, rt_walker->interface)->neighbor_rid;
        // print_lsu_ad(lsu_ad);
        lsu_ad = (uint8_t *)lsu_ad + sizeof(struct ospfv2_lsu);
        rt_walker = rt_walker->next;
    }
    // printf("Ad generation complete\n");

    // lsu_ad = (struct ospfv2_lsu *) ((uint8_t *) lsu_hdr + sizeof(struct ospfv2_lsu_hdr));

    // and send out the advertisements
    if_walker = sr->if_list;
    while (if_walker)
    {
        if (if_walker->neighbor_ip == 0)
        {
            if_walker = if_walker->next;
            continue;
        }

        memcpy(eth->ether_shost, if_walker->addr, sizeof(eth->ether_shost));

        uint32_t dest_ip = if_walker->neighbor_ip;
        ip->ip_src.s_addr = if_walker->ip;
        ip->ip_dst.s_addr = dest_ip;
        ip->ip_sum = 0;
        ip->ip_sum = cksum((void *)ip, ip->ip_hl * 4 / 2);

        ospf_hdr->csum = 0;
        ospf_hdr->csum = cksum((void *)ospf_hdr, (sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr) + ad_count * sizeof(struct ospfv2_lsu)) / 2);

        // TRAVERSE ARP CACHE TABLE FOR IP START **************************
        ARP_Cache *cache_temp = &(sr->arp_head);
        // I probably don't need this loop actually
        while (cache_temp != NULL)
        {
            unsigned char *haddr = entry_exists_in_cache(cache_temp, dest_ip);
            if (haddr != NULL)
            {
                // modify the ethernet header,
                memcpy(eth->ether_dhost, haddr, sizeof(eth->ether_dhost));
                memcpy(eth->ether_shost, if_walker->addr, sizeof(eth->ether_shost));

                // then send off the packet.
                int rc = sr_send_packet(sr, lsu_packet, lsu_len, if_walker->name);
                assert(rc == 0);
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
                wait_in_queue(check_buf, lsu_packet, lsu_len);

                send_arp_req(sr, lsu_packet, if_walker->name, dest_ip);
                // otherwise, we queue the packet to wait for that ARP response.
            }
            else
            {
                wait_in_queue(check_buf, lsu_packet, lsu_len);
            }
        }
        // TRAVERSE ARP CACHE TABLE FOR IP END **************************

        if_walker = if_walker->next;
    }

    free(lsu_packet);
}

/*---------------------------------------------------------------------
 * Method: pwospf_run_thread
 *
 * Main thread of pwospf subsystem.
 *
 *---------------------------------------------------------------------*/

static void *pwospf_run_thread(void *arg)
{
    struct sr_instance *sr = (struct sr_instance *)arg;
    uint32_t hello_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr);
    uint8_t hello_packet[hello_len];

    struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr *)hello_packet;
    // make destination MAC bits all 1
    for (int i = 0; i < ETHER_ADDR_LEN; ++i)
        eth->ether_dhost[i] = ~(eth->ether_dhost[i] & 0);
    eth->ether_type = ntohs(ETHERTYPE_IP);

    // INITIALIZE IP HEADER START **********
    struct ip *ip = (struct ip *)(hello_packet + sizeof(struct sr_ethernet_hdr));
    ip->ip_v = 4;
    ip->ip_hl = 5;
    ip->ip_tos = 0; // normal
    ip->ip_len = htons(sizeof(struct ip) + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr));
    ip->ip_id = 0;
    ip->ip_off = 0;
    ip->ip_ttl = 255; // max ttl put here
    ip->ip_p = IPROTO_OSPF;
    ip->ip_dst.s_addr = htonl(OSPF_AllSPFRouters); // 244.0.0.5
    // INITIALIZE IP HEADER END   **********

    // INITIALIZE OSPF HEADER START ********
    struct ospfv2_hdr *ospf_hdr = (struct ospfv2_hdr *)((uint8_t *)ip + sizeof(struct ip));
    //(hello_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
    ospf_hdr->version = (OSPF_V2);
    ospf_hdr->type = OSPF_TYPE_HELLO;
    ospf_hdr->len = sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr);
    ospf_hdr->rid = sr_get_interface(sr, "eth0")->ip;
    ospf_hdr->aid = 0;
    ospf_hdr->autype = 0;
    ospf_hdr->audata = 0;

    struct ospfv2_hello_hdr *hello_hdr = (struct ospfv2_hello_hdr *)((uint8_t *)ospf_hdr + sizeof(struct ospfv2_hdr));
    //(ospf_hdr + sizeof(struct ospfv2_hdr));
    hello_hdr->helloint = OSPF_DEFAULT_HELLOINT;
    // INITIALIZE OSPF HEADER END   ********

    int hello_cnt = 0, update_cnt = 0;
    char need_update = 0;
    while (1)
    {
        need_update = 0;
        pwospf_lock(sr->ospf_subsys);
        need_update = check_timeout(sr);

        if (hello_cnt % OSPF_DEFAULT_HELLOINT == 0)
        {
            hello_cnt = 0;
            hello_all(sr, hello_packet, hello_len);
        }
        if (update_cnt % OSPF_DEFAULT_LSUINT == 0 || need_update)
        {
            send_updates(sr);
            update_cnt = 0;
        }

        // printf("Done checking timeout.\n");
        if (need_update)
            recalculate_rt(sr);

        pwospf_unlock(sr->ospf_subsys);
        sleep(1);
        hello_cnt++;
        update_cnt++;
    };

    free(hello_packet);

    return NULL;
} /* -- run_ospf_thread -- */

void hello_all(struct sr_instance *sr, uint8_t *packet, uint32_t len)
{
    // going through the interface list,
    struct sr_if *if_walker = 0;
    if_walker = sr->if_list;

    struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr *)packet;
    struct ip *ip = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
    struct ospfv2_hdr *ospf_hdr = (struct ospfv2_hdr *)((uint8_t *)ip + sizeof(struct ip));
    struct ospfv2_hello_hdr *hello_hdr = (struct ospfv2_hello_hdr *)((uint8_t *)ospf_hdr + sizeof(struct ospfv2_hdr));

    while (if_walker)
    {
        memcpy(eth->ether_shost, if_walker->addr, sizeof(eth->ether_shost));
        ip->ip_src.s_addr = if_walker->ip;
        ip->ip_sum = 0;
        ip->ip_sum = cksum((void *)ip, ip->ip_hl * 4 / 2); // put it as blank for now

        hello_hdr->nmask = if_walker->mask; // set when sending hello
        ospf_hdr->csum = 0;
        ospf_hdr->csum = cksum((void *)ospf_hdr, (sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr)) / 2); // need to figure out how to calculate this, likely happens before send
        int rc = sr_send_packet(sr, packet, len, if_walker->name);
        assert(rc == 0);
        if_walker = if_walker->next;
    }
}

int pwospf_init(struct sr_instance *sr)
{
    assert(sr);

    sr->ospf_subsys = (struct pwospf_subsys *)malloc(sizeof(struct
                                                            pwospf_subsys));

    assert(sr->ospf_subsys);
    pthread_mutex_init(&(sr->ospf_subsys->lock), 0);

    /* -- handle subsystem initialization here! -- */
    sr->ospf_subsys->head_router.next = NULL;
    sr->ospf_subsys->head_router.head.next = NULL;
    sr->ospf_subsys->curr_seq = 1;

    // initialize routing table
    struct sr_if *if_walker = 0;
    if_walker = sr->if_list;

    // need to set static to 0
    struct sr_rt *rt_walker = sr->routing_table;
    while (rt_walker != NULL)
    {
        rt_walker->static_flag = 1;
        rt_walker = rt_walker->next;
    }

    struct in_addr dest, gw, mask;
    while (if_walker)
    {
        dest.s_addr = if_walker->ip;
        gw.s_addr = 0;
        mask.s_addr = if_walker->mask;
        if (!interface_exists(sr, if_walker->name))
        {
            sr_add_rt_entry(sr, dest, gw, mask, if_walker->name);
        }
        if_walker = if_walker->next;
    }

    /* -- start thread subsystem -- */
    if (pthread_create(&sr->ospf_subsys->thread, 0, pwospf_run_thread, sr))
    {
        perror("pthread_create");
        assert(0);
    }

    return 0; /* success */
} /* -- pwospf_init -- */

/*---------------------------------------------------------------------
 * Method: pwospf_lock
 *
 * Lock mutex associated with pwospf_subsys
 *
 *---------------------------------------------------------------------*/
void pwospf_lock(struct pwospf_subsys *subsys)
{
    if (pthread_mutex_lock(&subsys->lock))
    {
        assert(0);
    }
    // printf("Locking.\n");
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_unlock
 *
 * Unlock mutex associated with pwospf subsystem
 *
 *---------------------------------------------------------------------*/
void pwospf_unlock(struct pwospf_subsys *subsys)
{
    if (pthread_mutex_unlock(&subsys->lock))
    {
        assert(0);
    }
    // printf("Unlocking.\n");
} /* -- pwospf_subsys -- */
