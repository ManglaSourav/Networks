
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include "sr_router.h"
#include "top_db.h"

//returns the node if exists, NULL if does not
Router *checkRouterExists(Router *head, uint32_t rid) {
	Router *curr = head;
	while(curr->next != NULL && (curr->next)->rid != rid) {
		curr = curr->next;
	}

	if(curr->next != NULL) {
		return curr->next; //we found it.
	}

	return NULL;
}

void deleteRouter(Router *head, uint32_t rid) {
	Router *curr = head;

  // we attempt to locate the router
	while(curr->next != NULL && (curr->next)->rid != rid) {
		curr = curr->next;
	}

  //if we can find the router, attempt to remove it
	if(curr->next != NULL) {
    Router *temp_router = curr->next;
    curr->next = temp_router->next;

    // loop through and remove all links
    Link *curr_link = &(temp_router->head), *temp_link = NULL;
    while(curr_link->next != NULL) {
      temp_link = curr_link->next;
      curr_link->next = temp_link->next;
      free(temp_link);
    }
    free(temp_router);
	} else {
    // if we tried to delete a router that DNE, should say something
    struct in_addr ip_addr;
    ip_addr.s_addr = rid;
    printf("Router with rid %s was not found\n", inet_ntoa(ip_addr));
  }
}

//inserts router at beginning of linked list
Router *insertNewRouter(Router *head, uint32_t rid) {
  Router *new = (Router *) malloc(sizeof(Router));
  new->rid = rid;
  new->head.next = NULL;
  new->seq = 0;
  new->traversed = 0;
  updateTime(new);

	Router *temp = head->next;
	head->next = new;
	new->next = temp;
  //printf("%d\n", head->next->rid);

  return new;
}

void updateTime(Router *spot){
	spot->time = time(0);
}
void addLink(Router *spot, uint32_t ip, uint32_t mask, uint32_t rid) {
  Link *new = (Link *) malloc(sizeof(Link));
  new->ip = ip;
  new->mask = mask;
  new->rid = rid;

  Link *temp = spot->head.next;
  spot->head.next = new;
	new->next = temp;
}

void removeLink(Router *spot, uint32_t ip, uint32_t mask, uint32_t rid) {
  // loop through and find the link we want to remove
  Link *curr_link = &(spot->head), *temp_link = NULL;
  while(curr_link->next != NULL && (curr_link->next->ip != ip || curr_link->next->mask != mask || curr_link->next->rid != rid)) {
    curr_link = curr_link->next;
  }

  if(curr_link->next != NULL) {
    temp_link = curr_link->next;
    curr_link->next = temp_link->next;
  }
}


void removeAllLinks(Router *spot) {
  // loop through and remove all links
  Link *curr_link = &(spot->head), *temp_link = NULL;
  while(curr_link->next != NULL) {
    temp_link = curr_link->next;
    curr_link->next = temp_link->next;
    free(temp_link);
  }
}


Link *findLink(Router *head, uint32_t rid, uint32_t ip, uint32_t mask) {
	Router *curr = head;
  struct in_addr temp;
  temp.s_addr = rid;
  //printf("Finding link with %s\n", inet_ntoa(temp));
    temp.s_addr = ip;
    //printf("Finding subnet %s\n", inet_ntoa(temp));

	while(curr->next != NULL && (curr->next)->rid != rid) {
		curr = curr->next;
	}

	if(curr->next != NULL) {
    //printf("Found router, looking for link\n");
		Link *curr_link = &(curr->next->head);
    while(curr_link->next != NULL) {
      temp.s_addr = curr_link->next->ip;
      //printf("Find Lnk addr: %s\n", inet_ntoa(temp));
      if((curr_link->next->ip & curr_link->next->mask) == (ip & mask)) {
        //printf("Found it, now we are returning.\n");
        return curr_link->next;
      }

      curr_link = curr_link->next;
    }
	}

	return NULL;

}

