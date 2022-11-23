/*-----------------------------------------------------------------------------
 * file:  sr_pwospf.h
 * date:  Tue Nov 23 23:21:22 PST 2004 
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_PWOSPF_H
#define SR_PWOSPF_H

#include <pthread.h>

//TODO:
#include "Router_Helper.h"

#ifndef IPROTO_OSPF
#define IPROTO_OSPF 89
#endif
//

/* forward declare */
struct sr_instance;

struct pwospf_subsys
{
    /* -- pwospf subsystem state variables here -- */
    uint32_t state_seq;
    Router head_router;
    /* -- thread and single lock for pwospf subsystem -- */
    pthread_t thread;
    pthread_mutex_t lock;
};

int pwospf_init(struct sr_instance* sr);
void pwospf_lock(struct pwospf_subsys *subsys);
void pwospf_unlock(struct pwospf_subsys *subsys);
void calculate_rt(struct sr_instance *sr);
void post_updates(struct sr_instance *sr);
void say_hello(struct sr_instance *sr, uint8_t *packet, uint32_t len);
char check_timeout(struct sr_instance *sr);


#endif /* SR_PWOSPF_H */
