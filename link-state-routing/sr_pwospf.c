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
#include "sr_if.h"
#include "sr_rt.h"
#include "Packet_Helper.h"
#include "sr_router.h"
#include "sr_pwospf.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "pwospf_protocol.h"

static void *pwospf_run_thread(void *arg);

char check_timeout(struct sr_instance *sr)
{
    Router *curr_router = &(sr->ospf_subsys->head_router);
    char temp = 0;
    time_t curr_time = time(0);
    struct in_addr t_addr;
    while (curr_router->next != NULL)
    {
        if (curr_time - curr_router->next->time >= 10)
        { // Link down detected
            struct sr_if *iface = sr_get_interface_n_rid(sr, curr_router->next->rid);
            iface->up = 0;
            iface->neighbor_ip = 0;
            iface->neighbor_rid = 0;
            struct sr_rt *curr_rt = sr->routing_table, *t = NULL;
            while (strcmp(curr_rt->interface, iface->name) == 0 && !(curr_rt->static_flag))
            {
                t_addr = curr_rt->dest;
                t = curr_rt;
                sr->routing_table = t->next;
                curr_rt = sr->routing_table;
                temp = 1;
                free(t);
            }

            while (curr_rt->next != NULL)
            {
                t_addr = curr_rt->next->dest;
                if (strcmp(curr_rt->next->interface, iface->name) == 0 && !(curr_rt->next->static_flag))
                {
                    t_addr = curr_rt->next->dest;
                    t = curr_rt->next;
                    curr_rt->next = t->next;
                    free(t);
                    temp = 1;
                }
                else
                    curr_rt = curr_rt->next;
            }
            delete_Router(&(sr->ospf_subsys->head_router), curr_router->next->rid);
        }
        else
            curr_router = curr_router->next;
    }
    return temp;
}

/*---------------------------------------------------------------------
 * Method: calculate_rt(..)
 * internal structure is initialized here
 *---------------------------------------------------------------------*/
void calculate_rt(struct sr_instance *sr)
{
    struct sr_if *if_handler = sr->if_list;
    struct sr_rt *rt_handler = sr->routing_table;
    Router *router = NULL;
    while (if_handler != NULL)
    {
        if (!(if_handler->up))
        {
            if_handler = if_handler->next;
            continue;
        }
        rt_handler = sr->routing_table;
        while (rt_handler != NULL)
        {
            if ((if_handler->mask & if_handler->ip) == (rt_handler->mask.s_addr & rt_handler->dest.s_addr) && if_handler->mask > 0)
                break;
            rt_handler = rt_handler->next;
        }
        if (rt_handler == NULL)
        {
            struct in_addr dest, gw, mask;
            dest.s_addr = if_handler->ip;
            gw.s_addr = if_handler->neighbor_ip;
            mask.s_addr = if_handler->mask;
            sr_add_rt_entry(sr, dest, gw, mask, if_handler->name);
        }
        if_handler = if_handler->next;
    }
    router = NULL;
    if_handler = sr->if_list;
    while (if_handler != NULL)
    {
        if (if_handler->neighbor_rid == 0)
        {
            if_handler = if_handler->next;
            continue;
        }
        router = check_Router_Exists(&(sr->ospf_subsys->head_router), if_handler->neighbor_rid);
        if (router == NULL)
        {
            struct in_addr temp;
            temp.s_addr = if_handler->neighbor_rid;
        }
        else
        {
            struct in_addr temp_inaddr;
            temp_inaddr.s_addr = if_handler->neighbor_rid;
        }

        Link *link_handler = router->head.next;
        while (link_handler != NULL)
        {
            if (link_handler->rid == sr_get_interface(sr, "eth0")->ip)
            {
                link_handler = link_handler->next;
                continue;
            }
            rt_handler = sr->routing_table;
            while (rt_handler != NULL)
            {
                if ((link_handler->mask & link_handler->ip) == (rt_handler->mask.s_addr & rt_handler->dest.s_addr))
                {
                    struct sr_if *t_iface = sr_get_interface(sr, rt_handler->interface);
                    if (link_handler->rid == t_iface->neighbor_rid)
                        break;
                    if (rt_handler->gw.s_addr == 0)
                        break;
                    if (rt_handler->static_flag)
                        break;

                    Link *temp_link = search_Link(&(sr->ospf_subsys->head_router),
                                                  t_iface->neighbor_rid,
                                                  rt_handler->dest.s_addr,
                                                  rt_handler->mask.s_addr);

                    if (temp_link == NULL)
                        if (temp_link->rid == link_handler->rid)
                        {
                            rt_handler->dest.s_addr = link_handler->ip;
                            rt_handler->mask.s_addr = link_handler->mask;
                            rt_handler->gw.s_addr = if_handler->neighbor_ip;
                            memcpy(rt_handler->interface, if_handler->name, sizeof(char) * SR_IFACE_NAMELEN);
                        }
                    break;
                }
                rt_handler = rt_handler->next;
            }
            if (rt_handler == NULL)
            {
                struct in_addr dest, gw, mask;
                dest.s_addr = link_handler->ip;
                if (link_handler->mask)
                    gw.s_addr = if_handler->neighbor_ip;
                mask.s_addr = link_handler->mask;
                sr_add_rt_entry(sr, dest, gw, mask, if_handler->name);
            }
            link_handler = link_handler->next;
        }

        if_handler = if_handler->next;
    }
}

/*---------------------------------------------------------------------
 * Method: post_updates(struct sr_instance* sr)
 *
 *This method is called when the packet received by the router is
 *identified to have a type of IP.
 *---------------------------------------------------------------------*/
void post_updates(struct sr_instance *sr)
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
    lsu_hdr->seq = sr->ospf_subsys->state_seq;
    sr->ospf_subsys->state_seq++;

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
            say_hello(sr, hello_packet, hello_len);
        }
        if (update_cnt % OSPF_DEFAULT_LSUINT == 0 || need_update)
        {
            post_updates(sr);
            update_cnt = 0;
        }

        // printf("Done checking timeout.\n");
        if (need_update)
            calculate_rt(sr);

        pwospf_unlock(sr->ospf_subsys);
        sleep(1);
        hello_cnt++;
        update_cnt++;
    };

    free(hello_packet);

    return NULL;
} /* -- run_ospf_thread -- */

void say_hello(struct sr_instance *sr, uint8_t *packet, uint32_t len)
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
    sr->ospf_subsys->state_seq = 1;
    sr->ospf_subsys->head_router.head.next = NULL;

    // initialize routing table
    struct sr_if *if_handler = 0;
    if_handler = sr->if_list;

    struct sr_rt *rt_walker = sr->routing_table;
    struct in_addr dest, gw, mask;
    while (rt_walker != NULL)
    {
        rt_walker->static_flag = 1;
        rt_walker = rt_walker->next;
    }
    while (if_handler)
    {
        dest.s_addr = if_handler->ip;
        gw.s_addr = 0;
        mask.s_addr = if_handler->mask;
        if (!if_exists(sr, if_handler->name))
            sr_add_rt_entry(sr, dest, gw, mask, if_handler->name);
        if_handler = if_handler->next;
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
