#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "sr_protocol.h"
#include "ARP_Helper.h"
#include "sr_router.h"
#include "router_helper.h"
#include "sr_if.h"
#include "sr_rt.h"

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
