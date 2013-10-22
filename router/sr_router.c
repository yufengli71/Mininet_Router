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
#include <stdlib.h>
#include <string.h>

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
	sr_arp_hdr_t *arp_hdr, *arp_reply_hdr = 0;
	sr_ethernet_hdr_t *ether_hdr, *queuing_ether = 0;
	uint8_t *reply_packet = 0;
	struct sr_if *iface = 0;
	struct sr_arpreq *arpreq = 0;
	struct sr_packet *queuing_packet = 0;
	
	/* check if header has the correct size */
	if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
		fprintf(stderr, "Error: invalid ARP header length\n");
		return;
	}
	
	arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
	
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
		if ((reply_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))) == NULL) {
			fprintf(stderr,"Error: out of memory (sr_handlearp)\n");
			return;
		}
				
		/* construct ARP header */
		arp_reply_hdr = (sr_arp_hdr_t*)(reply_packet + sizeof(sr_ethernet_hdr_t));
		arp_reply_hdr->ar_hrd = htons(arp_hrd_ethernet);            /* format of hardware address   */
		arp_reply_hdr->ar_pro = htons(ethertype_ip);		        /* format of protocol address   */
		arp_reply_hdr->ar_hln = htons(ETHER_ADDR_LEN);	            /* length of hardware address   */
		arp_reply_hdr->ar_pln = htons(4);             				/* length of protocol address   */
		arp_reply_hdr->ar_op = htons(arp_op_reply);             	/* ARP opcode (command)         */
		memcpy(arp_reply_hdr->ar_sha, iface->addr, sizeof(iface->addr));   				/* sender hardware address      */
		arp_reply_hdr->ar_sip = htonl(iface->ip);   				/* sender IP address            */
		memcpy(arp_reply_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);   					/* target hardware address      */
		arp_reply_hdr->ar_tip = arp_hdr->ar_sip;        				/* target IP address            */
		
		/* construct ethernet header */
		ether_hdr = (sr_ethernet_hdr_t*)reply_packet;
		memcpy(ether_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
		memcpy(ether_hdr->ether_shost, iface->addr, sizeof(iface->addr));
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
		if (arp_hdr->ar_tha != iface->addr) {
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
				queuing_ether = (sr_ethernet_hdr_t *)(queuing_packet->buf);
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


uint8_t* sr_generate_icmp(sr_ethernet_hdr_t *received_ether_hdr, 
						  sr_ip_hdr_t *received_ip_hdr, 
						  struct sr_if *iface, 
						  uint8_t type, uint8_t code)
{
	uint8_t *reply_packet = 0;
	sr_icmp_hdr_t *icmp_hdr = 0;
	sr_ip_hdr_t *ip_hdr = 0;
	sr_ethernet_hdr_t *ether_hdr = 0;
	size_t icmp_size = 0;
	
	/* type 0 echo reply */
	if (type == 0) {
	
		/* create new reply packet */
		if ((reply_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t))) == NULL) {
			fprintf(stderr,"Error: out of memory (sr_generate_icmp)\n");
			return 0;
		}
		
		/* construct ICMP header */
		icmp_hdr = (sr_icmp_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		icmp_hdr->icmp_type = htons(type);
		icmp_hdr->icmp_code = htons(code);
		icmp_hdr->icmp_sum = htons(0);
		icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t));
		
		/* grab the size of ICMP header */
		icmp_size = sizeof(sr_icmp_hdr_t);
	}
	/* Destination net unreachable (type 3, code 0) OR Time exceeded (type 11, code 0),
	   since the two types use the exact same struct, except the next_mtu field which is unused for type 11 */
	else if (type == 3 || type == 11) {
	
		/* create new reply packet */
		if ((reply_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t))) == NULL) {
			fprintf(stderr,"Error: out of memory (sr_generate_icmp)\n");
			return 0;
		}
		
		/* construct ICMP header */
		icmp_hdr = (sr_icmp_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		icmp_hdr->icmp_type = htons(type);
		icmp_hdr->icmp_code = htons(code);
		icmp_hdr->unused = htons(0);
		icmp_hdr->next_mtu = htons(0);		
		if (type == 3) {	/* only set next_mtu if ICMP type is 3*/
			icmp_hdr->next_mtu = htons(1500);
		}
		memcpy(icmp_hdr->data, received_ip_hdr, ICMP_DATA_SIZE);
		icmp_hdr->icmp_sum = htons(0);
		icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
		
		/* grab the size of ICMP header */
		icmp_size = sizeof(sr_icmp_t3_hdr_t);
	}
	/* An ICMP type that we can't handle */
	else {
		fprintf(stderr,"Error: unsupported ICMP type (sr_generate_icmp)\n");
		return 0;
	}
	
	/* construct IP header */
	ip_hdr = (sr_ip_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
	ip_hdr->ip_hl = htons(5);									/* header length */
	ip_hdr->ip_v = htons(4);									/* version */
	ip_hdr->ip_tos = htons(0);									/* type of service */
	ip_hdr->ip_len = htons(20 + icmp_size);						/* total length */
	ip_hdr->ip_id = htons(0);									/* identification */
	ip_hdr->ip_off = htons(IP_DF);								/* fragment offset field */
	ip_hdr->ip_ttl = hotns(INIT_TTL);							/* time to live */
	ip_hdr->ip_p = hotns(ip_protocol_icmp);						/* protocol */
	ip_hdr->ip_src = htonl(iface->ip);							/* source ip address */
	ip_hdr->ip_dst = received_ip_hdr->ip_src;					/* dest ip address */
	ip_hdr->ip_sum = htons(0);
	ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));		/* checksum */
	
	/* construct ethernet header */
	ether_hdr = (sr_ethernet_hdr_t*)reply_packet;
	ether_hdr->ether_dhost = received_ether_hdr->ether_shost;
	ether_hdr->ether_shost = htons(iface->addr);
	ether_hdr->ether_type = htons(ethertype_ip);
			
	return reply_packet;
}


void sr_handleip(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	sr_ip_hdr_t *ip_hdr = 0;
	struct sr_if *iface = 0;
	sr_icmp_hdr_t *icmp_hdr = 0;
	uint8_t *reply_packet = 0;
	struct sr_rt *rt = 0;
	uint32_t nexthop_ip, longest_mask = 0;
	struct sr_arpentry *arp_entry = 0;
	struct sr_arpreq *arp_rep = 0;
	sr_ethernet_hdr_t *ether_hdr = 0;
	
	/* check if header has the correct size */
	if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
		fprintf(stderr, "Error: invalid IP header length\n");
		return;
	}
	
	ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
	
	/* perform ip header checksum */
	if (cksum(ip_hdr, ip_hdr->ip_hl) != 0xffff) {
		fprintf(stderr, "Error: IP checksum failed\n");
		return;
	}
	
	/* grab the receiving interface */
	if ((iface = sr_get_interface(sr, interface)) == 0) {
		fprintf(stderr, "Error: interface does not exist (sr_handleip)\n");
		return;
	}
	
	/* if the packet is destined to our ip */
	if (ip_hdr->ip_dst == htonl(iface->ip)) {
	
		/* if it is an ICMP */
		if (ip_hdr->ip_p == htons(ip_protocol_icmp)) {
			
			/* check if header has the correct size */
			if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)) {
				fprintf(stderr, "Error: invalid ICMP header length\n");
				return;
			}
			
			icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
			
			/* if it is an ICMP echo request, send an ICMP echo reply */
			if (icmp_hdr->icmp_type == htons(8) && icmp_hdr->icmp_code == htons(0)) {
				
				/* perform ICMP header checksum */
				if (cksum(icmp_hdr, sizeof(icmp_hdr)) != 0xffff) {
					fprintf(stderr, "Error: ICMP checksum failed\n");
					return;
				}
				
				/* generate an echo reply packet */
				if ((reply_packet = sr_generate_icmp((sr_ethernet_hdr_t *)packet, ip_hdr, iface, 0, 0)) == 0) {
					fprintf(stderr, "Error: failed to generate ICMP echo reply packet\n");
					return;
				}
				
				/* send an ICMP echo reply */
				if (sr_send_packet(sr, reply_packet, sizeof(reply_packet), (const char*)interface) == -1) {
					fprintf(stderr, "Error: sending packet failed (sr_handleip)\n");
				}
				
				free(reply_packet);				
			}
		}
		/* if it contains a TCP or UDP payload */
		else {
		
			/* generate Destination net unreachable (type 3, code 0) reply packet */
			if ((reply_packet = sr_generate_icmp((sr_ethernet_hdr_t *)packet, ip_hdr, iface, 3, 3)) == 0) {
				fprintf(stderr, "Error: failed to generate ICMP packet\n");
				return;
			}
			
			/* send an ICMP */
			if (sr_send_packet(sr, reply_packet, sizeof(reply_packet), (const char*)interface) == -1) {
				fprintf(stderr, "Error: sending packet failed (sr_handleip)\n");
			}
			
			free(reply_packet);		
		}
	}
	/* packet not for us, forward it */
	else {
		
		/* if TTL reaches 0 */
		if (ip_hdr->ip_ttl <= htons(1)) {
		
			/* generate Time exceeded (type 11, code 0) reply packet */
			if ((reply_packet = sr_generate_icmp((sr_ethernet_hdr_t *)packet, ip_hdr, iface, 11, 0)) == 0) {
				fprintf(stderr, "Error: failed to generate ICMP packet\n");
				return;
			}
			
			/* send an ICMP */
			if (sr_send_packet(sr, reply_packet, sizeof(reply_packet), (const char*)interface) == -1) {
				fprintf(stderr, "Error: sending packet failed (sr_handleip)\n");
			}
			
			free(reply_packet);
		}
		/* if packet has enough TTL */
		else {
			
			/* decrement the TTL by 1 */
			ip_hdr->ip_ttl --;
			
			/* recompute the packet checksum */
			ip_hdr->ip_sum = htons(0);
			ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
			
			/* Find entry in the routing table with the longest prefix match */
			rt = sr->routing_table;
			while (rt != NULL) {
				
				/* update the gateway ip and the longest mask so far */
				if ((rt->dest.s_addr & rt->mask.s_addr) == (ntohl(ip_hdr->ip_dst) & rt->mask.s_addr) &&
					rt->mask.s_addr > longest_mask) {
					nexthop_ip = rt->gw.s_addr;
					longest_mask = rt->mask.s_addr;
				}
				
				rt = rt->next;
			}
			
			/* if a matching routing table entry was NOT found */
			if (nexthop_ip == 0) {
				
				/* generate Destination net unreachable (type 3, code 0) reply packet */
				if ((reply_packet = sr_generate_icmp((sr_ethernet_hdr_t *)packet, ip_hdr, iface, 3, 0)) == 0) {
					fprintf(stderr, "Error: failed to generate ICMP packet\n");
					return;
				}
				
				/* send an ICMP */
				if (sr_send_packet(sr, reply_packet, sizeof(reply_packet), (const char*)interface) == -1) {
					fprintf(stderr, "Error: sending packet failed (sr_handleip)\n");
				}
				
				free(reply_packet);
			}
			/* if a matching routing table entry was found */
			else {
			
				/* set the source MAC of ethernet header */
				ether_hdr = (sr_ethernet_hdr_t*)packet;
				ether_hdr->ether_shost = htons(iface->addr);
				
				/* if the next-hop IP CANNOT be found in ARP cache */
				if ((arp_entry = sr_arpcache_lookup(&(sr->cache), htonl(nexthop_ip))) == NULL) {
					
					/* send an ARP request */
					arp_req = arpcache_queuereq(nexthop_ip, packet, len);
					handle_arpreq(arp_req, sr);
				}
				/* if the next-hop IP can be found in ARP cache */
				else {
					
					/* set the destination MAC of ethernet header */
					ether_hdr->ether_dhost = htons(arp_entry->mac);
					
					/* send the packet */
					if (sr_send_packet(sr, packet, sizeof(packet), (const char*)interface) == -1) {
						fprintf(stderr, "Error: sending packet failed (sr_handlearp)\n");
					}
					
					free(arp_entry);
				}
			}
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
  
  /* check if header has the correct size */
  if (len < sizeof(sr_ethernet_hdr_t)) {
	fprintf(stderr, "Error: invalid packet length (ether_hdr)\n");
	return;
  }
  
  switch (ethertype(packet)) {
  
	/* -------------       Handling ARP     -------------------- */
	case ethertype_arp:
		sr_handlearp(sr, packet, len, interface);
		break;

	/* -------------       Handling IP      -------------------- */
	case ethertype_ip:
		sr_handleip(sr, packet, len, interface);
		break;

	default:
		fprintf(stderr, "Unknown ether_type: %d\n", ethertype(packet));
		break;

  }/* -- switch -- */
  

}/* end sr_ForwardPacket */

