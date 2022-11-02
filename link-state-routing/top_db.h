
#ifndef TOP_DB
#define TOP_DB

#include <time.h>

typedef struct Link {	
	uint32_t ip;
	uint32_t mask;
	uint32_t rid; // which router in our adj list
	struct Link *next;
} Link;

typedef struct Router {
	time_t time;
	uint32_t rid;
	Link head;
	uint16_t seq;
	char traversed;
	struct Router *next;
} Router;


Router *checkRouterExists(Router *head, uint32_t rid);
void deleteRouter(Router *head, uint32_t rid);
Router *insertNewRouter(Router *head, uint32_t rid);

void updateTime(Router *spot);
void addLink(Router *spot, uint32_t ip, uint32_t mask, uint32_t rid);
void removeLink(Router *spot, uint32_t ip, uint32_t mask, uint32_t rid);
void removeAllLinks(Router *spot);
Link *findLink(Router *head,  uint32_t rid, uint32_t ip, uint32_t mask);
#endif
