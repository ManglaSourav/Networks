
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include "sr_router.h"
#include "Router_Helper.h"

// returns the router node if exists, NULL otherwise
Router *check_Router_Exists(Router *head, uint32_t rid)
{
  Router *curr = head;
  while (curr->next != NULL && (curr->next)->rid != rid)
    curr = curr->next;
  if (curr->next != NULL)
    return curr->next; // found the node
  return NULL;
}

void delete_Router(Router *head, uint32_t rid)
{
  Router *curr = head;
  while (curr->next != NULL && (curr->next)->rid != rid)
    curr = curr->next;

  if (curr->next != NULL)
  { // remove the router after searching
    Router *t_router = curr->next;
    curr->next = t_router->next;
    Link *curr_link = &(t_router->head), *t_link = NULL; // remove all links
    while (curr_link->next != NULL)
    {
      t_link = curr_link->next;
      curr_link->next = t_link->next;
      free(t_link);
    }
    free(t_router);
  }
  else
  {
    struct in_addr ip_addr;
    ip_addr.s_addr = rid;
    printf("Router not found\n");
  }
}

// inserts router at the head of list
Router *insert_New_Router(Router *head, uint32_t rid)
{
  Router *new = (Router *)malloc(sizeof(Router));
  new->rid = rid;
  new->head.next = NULL;
  new->seq = 0;
  new->traversed = 0;
  update_Router_Time(new);
  Router *t = head->next;
  head->next = new;
  new->next = t;
  return new;
}

void update_Router_Time(Router *spot)
{
  spot->time = time(0);
}

// add a new Link to given router
void add_new_Link(Router *spot, uint32_t ip, uint32_t mask, uint32_t rid)
{
  Link *new_link = (Link *)malloc(sizeof(Link));
  new_link->ip = ip;
  new_link->mask = mask;
  new_link->rid = rid;

  Link *t = spot->head.next;
  spot->head.next = new_link;
  new_link->next = t;
}

// TODO:remove
void remove_Link(Router *spot, uint32_t ip, uint32_t mask, uint32_t rid)
{
  // Link *curr_link = &(spot->head), *t_link = NULL;
  // while (curr_link->next != NULL &&
  //        (curr_link->next->ip != ip || curr_link->next->mask != mask || curr_link->next->rid != rid))
  //   curr_link = curr_link->next;

  // if (curr_link->next != NULL)
  // {
  //   t_link = curr_link->next;
  //   curr_link->next = t_link->next;
  // }
}

void remove_All_Links(Router *spot)
{
  Link *curr_link = &(spot->head), *t_link = NULL;
  while (curr_link->next != NULL)
  {
    t_link = curr_link->next;
    curr_link->next = t_link->next;
    free(t_link);
  }
}

Link *search_Link(Router *head, uint32_t rid, uint32_t ip, uint32_t mask)
{
  struct in_addr t;
  t.s_addr = rid;
  t.s_addr = ip;
  Router *curr = head;

  while (curr->next != NULL && (curr->next)->rid != rid)
    curr = curr->next;

  if (curr->next != NULL)
  {
    Link *curr_link = &(curr->next->head);
    while (curr_link->next != NULL)
    {
      t.s_addr = curr_link->next->ip;
      if ((curr_link->next->ip & curr_link->next->mask) == (ip & mask))
        return curr_link->next;
      curr_link = curr_link->next;
    }
  }
  return NULL;
}
