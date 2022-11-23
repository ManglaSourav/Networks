
#ifndef Router_Helper
#define Router_Helper
#include <time.h>

typedef struct Link
{
	uint32_t ip;
	uint32_t mask;
	uint32_t rid; // for adjacent routers
	struct Link *next;
} Link;

typedef struct Router
{
	time_t time;
	uint32_t rid;
	Link head;
	uint16_t seq;
	char traversed;
	struct Router *next;
} Router;

void update_Router_Time(Router *spot);
void add_new_Link(Router *spot, uint32_t ip, uint32_t mask, uint32_t rid);
void remove_Link(Router *spot, uint32_t ip, uint32_t mask, uint32_t rid);
void remove_All_Links(Router *spot);
Link *search_Link(Router *head, uint32_t rid, uint32_t ip, uint32_t mask);
Router *check_Router_Exists(Router *head, uint32_t rid);
void delete_Router(Router *head, uint32_t rid);
Router *insert_New_Router(Router *head, uint32_t rid);

#endif
