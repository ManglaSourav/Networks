/*-----------------------------------------------------------------------------
 * file:  sr_rt.c
 * date:  Mon Oct 07 04:02:12 PDT 2002
 * Author:  casado@stanford.edu
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#define __USE_MISC 1 /* force linux to show inet_aton */
#include <arpa/inet.h>

#include "sr_rt.h"
#include "sr_router.h"

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

int sr_load_rt(struct sr_instance *sr, const char *filename)
{
    FILE *fp;
    char line[BUFSIZ];
    char dest[32];
    char gw[32];
    char mask[32];
    char iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;

    /* -- REQUIRES -- */
    assert(filename);
    if (access(filename, R_OK) != 0)
    {
        perror("access");
        return -1;
    }

    fp = fopen(filename, "r");

    while (fgets(line, BUFSIZ, fp) != 0)
    {
        if (EOF == sscanf(line, "%s %s %s %s", dest, gw, mask, iface))
            break;
        if (inet_aton(dest, &dest_addr) == 0)
        {
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    dest);
            return -1;
        }
        if (inet_aton(gw, &gw_addr) == 0)
        {
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    gw);
            return -1;
        }
        if (inet_aton(mask, &mask_addr) == 0)
        {
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    mask);
            return -1;
        }
        sr_add_rt_entry(sr, dest_addr, gw_addr, mask_addr, iface);
    } /* -- while -- */

    return 0; /* -- success -- */
} /* -- sr_load_rt -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_add_rt_entry(struct sr_instance *sr, struct in_addr dest,
                     struct in_addr gw, struct in_addr mask, char *if_name)
{
    struct sr_rt *rt_walker = 0;

    /* -- REQUIRES -- */
    assert(if_name);
    assert(sr);

    /* -- empty list special case -- */
    if (sr->routing_table == 0)
    {
        sr->routing_table = (struct sr_rt *)malloc(sizeof(struct sr_rt));
        sr->routing_table->next = 0;
        sr->routing_table->dest = dest;
        sr->routing_table->gw = gw;
        sr->routing_table->mask = mask;
        sr->routing_table->static_flag = 0;

        strncpy(sr->routing_table->interface, if_name, SR_IFACE_NAMELEN);

        return;
    }

    /* -- find the end of the list -- */
    rt_walker = sr->routing_table;
    while (rt_walker->next)
    {
        rt_walker = rt_walker->next;
    }

    rt_walker->next = (struct sr_rt *)malloc(sizeof(struct sr_rt));
    rt_walker = rt_walker->next;

    rt_walker->next = 0;
    rt_walker->dest = dest;
    rt_walker->gw = gw;
    rt_walker->mask = mask;
    rt_walker->static_flag = 0;
    strncpy(rt_walker->interface, if_name, SR_IFACE_NAMELEN);

} /* -- sr_add_entry -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_table(struct sr_instance *sr)
{
    struct sr_rt *rt_walker = 0;

    if (sr->routing_table == 0)
    {
        printf(" Routing table empty \n");
        return;
    }

    rt_walker = sr->routing_table;

    sr_print_routing_entry(rt_walker);
    while (rt_walker->next)
    {
        rt_walker = rt_walker->next;
        sr_print_routing_entry(rt_walker);
    }

} /* -- sr_print_routing_table -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_entry(struct sr_rt *entry)
{
    /* -- REQUIRES --*/
    assert(entry);
    assert(entry->interface);

    printf("Destination: %s\n", inet_ntoa(entry->dest));
    printf("  Gateway : %s\n", inet_ntoa(entry->gw));
    printf("  Mask : %s\n", inet_ntoa(entry->mask));
    printf("  Interface : %s\n", entry->interface);

} /* -- sr_print_routing_entry -- */

char interface_exists(struct sr_instance *sr, char *name)
{
    struct sr_rt *rt_walker = 0;

    if (sr->routing_table == 0)
    {
        printf(" Routing table empty \n");
        return 0;
    }

    rt_walker = sr->routing_table;

    while (rt_walker != NULL)
    {
        if (strcmp(rt_walker->interface, name) == 0)
        {
            return 1;
        }
        rt_walker = rt_walker->next;
    }

    return 0;
} /* -- sr_print_routing_table -- */