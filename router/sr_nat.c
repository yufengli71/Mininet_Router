
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>

#include "sr_if.h"
#include "sr_protocol.h"


int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  nat->qtimeout = 0;
  nat->est_it = 0;
  nat->tr_it = 0;
  nat->ports_used = uint16_t[NUM_PORTS];
  /* Initialize any variables here */

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */
  struct sr_nat_mapping *mappings, *nxt;
  struct sr_nat_connection *conn, *nxt_conn;
  for(mappings = nat->mappings; mappings; mappings = nxt) {
	  nxt = mappings->next;
	  /*mappings->next = NULL;*/
	  for(conn = mappings->conns; conn; conn=nxt_conn) {
		  nxt_conn = conn->next;
		  free(conn);
	  }
	  free(mappings);
  }
 
  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */
	struct sr_nat_mapping *mappings, *nxt_map, *prev;
	
	/* give one second for most recent insert before checking for timeout */
	if (difftime(curtime, nat->mappings->last_updated) <= 1.0) {
		break;
	}
	/* iterate through mappings table and free mappings which have not been
	 * updated within the timeout specified. */
	for (mappings = nat->mappings; mappings; mappings=nxt_map) {
		nxt_map = mappings->next;
		if (mappings->type == nat_mapping_icmp) {
			if (difftime(curtime,  mappings->last_updated) > nat->qtimeout) {
				if (prev != NULL) {
					prev->next = nxt_map;		
				} 
				mappings->next = NULL;
				/* free(mappings->conns);*/
				nat->ports_used[mappings->aux_ext] = 0;
				free(mappings);
			}
		} else if (mappings->type == nat_mapping_tcp) {
			struct sr_nat_connection *conn, *nxt_conn, *prev;
			/* iterate through the connections and remove those that timed out */
			for (conn = mappings->conns; conn; conn=nxt_conn) {
				nxt_conn = conn->next;
				time_t diff = difftime(curtime, conn->last_active);
				if (conn->status == nat_conn_established) {
					if (diff > nat->est_it) {
						if (prev != NULL) {
							prev->next = nxt_conn;							
						}
						conn->next = NULL;
						free(conn);
					} 
				} else if (conn->status == nat_conn_transitory) {
					if (diff > nat->tr_it) {
						if (prev != NULL) {
							prev->next = nxt_conn;							
						}
						conn->next = NULL;
						free(conn);
					}
				}
			}
			/* If mapping has no active connections left, remove mapping */
			if (mappings->conns == NULL) {
				if (prev != NULL) {
					prev->next = nxt_map;		
				}
				mappings->next = NULL;
				nat->ports_used[mappings->aux_ext] = 0;
				free(mappings);
			}
		}		
		
		mappings = nxt_map;
	}
    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = malloc(sizeof(struct sr_nat_mapping));
  mapping->ip_int = ip_int;
  mapping->aux_int = aux_int;
  mapping->type = type;
  mapping->last_updated = time(NULL);
  mapping->conns = NULL;
  
  /* find free port to assign mapping to 1024-2047 */
  uint16_t nxt_prt = 0;
  for(nxt_prt; nxt_prt < NUM_PORTS; nxt_prt++) {
	  if (nat->ports_used[nxt_prt] == 0) {
		  break;
	  }
  } 
  mapping->aux_ext = 1024+nxt_prt;
  nat->ports_used[nxt_prt] == 1;
  
  /* get ext_ip */
  struct sr_if *ext_iface = sr_get_interface(nat->sr, nat->out_if_name);  
  mapping->ip_ext = ext_iface->ip;
  
  mapping->next = nat->mappings; /* add to front of table */
  pthread_mutex_unlock(&(nat->lock));
  
  struct sr_nat_mapping *copy = malloc(sizeof(struct sr_nat_mapping));
  memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
  return copy;
}
