/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

void sr_handlearp(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	struct sr_arp_hdr *arp_hdr, *arp_reply_hdr = 0;
	struct sr_ethernet_hdr *ether_hdr, *queuing_ether = 0;
	uint8_t *reply_packet = 0;
	struct sr_if *iface = 0;
	struct sr_arpreq *arpreq = 0;
	struct sr_packet *queuing_packet = 0;
	
	/* check if header has the correct size */
	if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr)) {
		fprintf(stderr, "Error: invalid ARP header length\n");
		return;
	}
	
	arp_hdr = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
	
	/* check if ARP hardware type is ethernet */
	if (arp_hdr->ar_hrd != htons(arp_hrd_ethernet)) {
		fprintf(stderr, "Error: unknown ARP hardware format\n");
		return;
	}
	
	/* check if arp protocol type is ip */
	if (arp_hdr->ar_pro != htons(ethertype_ip)) {
		fprintf(stderr, "Error: unknown ARP protocol format\n");
		return;
	}
	
	/* grab the receiving interface */
	if ((iface = sr_get_interface(sr, interface)) == 0) {
		fprintf(stderr, "Error: interface does not exist (sr_handlearp)\n");
		return;
	}
	
	/* handle received ARP request */
	if (arp_hdr->ar_op == htons(arp_op_request)) {
		
		/* create new reply packet */
		if ((reply_packet = malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr))) == NULL) {
			fprintf(stderr,"Error: out of memory (sr_handlearp)\n");
			return;
		}
				
		/* construct ARP header */
		arp_reply_hdr = (struct sr_arp_hdr*)(reply_packet + sizeof(struct sr_ethernet_hdr));
		arp_reply_hdr->ar_hrd = htons(arp_hrd_ethernet);            /* format of hardware address   */
		arp_reply_hdr->ar_pro = htons(ethertype_ip);		        /* format of protocol address   */
		arp_reply_hdr->ar_hln = htons(ETHER_ADDR_LEN);	            /* length of hardware address   */
		arp_reply_hdr->ar_pln = htons(4);             				/* length of protocol address   */
		arp_reply_hdr->ar_op = htons(arp_op_reply);             	/* ARP opcode (command)         */
		arp_reply_hdr->ar_sha = htons(iface->addr);   				/* sender hardware address      */
		arp_reply_hdr->ar_sip = htonl(iface->ip);   				/* sender IP address            */
		arp_reply_hdr->ar_tha = arp_hdr->arsha;   					/* target hardware address      */
		arp_reply_hdr->ar_tip = arp_hdr->sip;        				/* target IP address            */
		
		/* construct ethernet header */
		ether_hdr = (struct sr_ethernet_hdr*)reply_packet;
		ether_hdr->ether_dhost = arp_hdr->arsha;
		ether_hdr->ether_shost = htons(iface->addr);
		ether_hdr->ether_type = htons(ethertype_arp);
		
		/* send the packet */
		if (sr_send_packet(sr, reply_packet, sizeof(reply_packet), (const char*)interface) == -1) {
			fprintf(stderr, "Error: sending packet failed (sr_handlearp)\n");
		}
		free(reply_packet);
	}
	
	/* handle received ARP reply */
	else if (arp_hdr->ar_op == htons(arp_op_reply)) {
	
		/* check if the target ip matches ours */
		if (arp_hdr->ar_tha != htons(iface->addr)) {
			fprintf(stderr, "Error: ARP reply does not match our MAC (sr_handlearp)\n");
			return;
		}
	
		/* check if the target ip matches ours */
		if (arp_hdr->ar_tip != htonl(iface->ip)) {
			fprintf(stderr, "Error: ARP reply does not match our ip (sr_handlearp)\n");
			return;
		}
		
		/* check if the ip is already in our cache */
		if (sr_arpcache_lookup(&(sr->cache), arp_hdr->ar_sip) != NULL) {
			fprintf(stderr, "Error: ARP reply ip already in cache (sr_handlearp)\n");
			return;
		}
		
		/* Insert the reply to our ARP cache and grab the list of packets waiting for this IP */
		if ((arpreq = sr_arpcache_insert(&(sr->cache), ntohs(arp_hdr->ar_sha), arp_hdr->ar_sip)) != NULL) {
		
			queuing_packet = arpreq->packets;
			
			/* loop through all queuing packets */
			while(queuing_packet != NULL) {
			
				/* fill in the MAC field */
				queuing_ether = (struct sr_ethernet_hdr *)(queuing_packet->buf);
				queuing_ether->ether_dhost = arp_hdr->ar_sha;
				
				/* send the queuing packet */
				if (sr_send_packet(sr, queuing_packet->buf, queuing_packet->len, (const char*)queuing_packet->iface) == -1) {
					fprintf(stderr, "Error: sending queuing packet failed (sr_handlearp)\n");
				}
				
				queuing_packet = queuing_packet->next;
			}
			
			/* destroy the request queue */
			sr_arpreq_destroy(&(sr->cache), arpreq);
		}
	}
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/
 
void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  struct sr_ethernet_hdr* ether_hdr = 0;
  
  ether_hdr = (struct sr_ethernet_hdr *)packet;
  
  /* check if header has the correct size */
  if (len < sizeof(struct sr_ethernet_hdr)) {
	fprintf(stderr, "Error: invalid packet length (ether_hdr)\n");
	return;
  }
  
  switch (ether_hdr->ether_type) {
	/* -------------       Handling ARP     -------------------- */
	case htons(ethertype_arp):
		sr_handlearp(sr, packet, len, interface);
		break;

	/* -------------       Handling IP      -------------------- */
	case htons(ethertype_ip):
		sr_handleip(sr, packet, len, interface);
		break;

	default:
		Debug("unknown ether_type: %d\n", ether_type);
		break;

  }/* -- switch -- */
  

}/* end sr_ForwardPacket */

