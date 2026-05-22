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
#include <time.h>

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
static void handle_arp_packet(struct sr_instance *sr, uint8_t *packet,
                              unsigned int len, char *interface);
static void handle_ip_packet(struct sr_instance *sr, uint8_t *packet,
                             unsigned int len, char *interface);

static void send_arp_request(struct sr_instance *sr, uint32_t target_ip_nbo,
                             const char *iface_name);
static void send_arp_reply(struct sr_instance *sr, sr_arp_hdr_t *req_arp,
                           struct sr_if *iface);

static void send_icmp_echo_reply(struct sr_instance *sr, uint8_t *orig,
                                 unsigned int len);
static void send_icmp_error(struct sr_instance *sr, uint8_t type, uint8_t code,
                            uint8_t *orig, unsigned int orig_len,
                            uint32_t src_ip_nbo);

static int route_and_send(struct sr_instance *sr, uint8_t *frame,
                          unsigned int len);
static struct sr_rt *rt_exact_match(struct sr_instance *sr, uint32_t ip_nbo);
static struct sr_if *find_iface_for_ip(struct sr_instance *sr,
                                       uint32_t ip_nbo);

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


/* main entry from sr_vns_comm; packet and interface are borrowed. */
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

  if (len < sizeof(sr_ethernet_hdr_t)) {
    return;
  }

  uint16_t etype = ethertype(packet);
  if (etype == ethertype_arp) {
    handle_arp_packet(sr, packet, len, interface);
  } else if (etype == ethertype_ip) {
    handle_ip_packet(sr, packet, len, interface);
  }
}/* end sr_ForwardPacket */

static void handle_arp_packet(struct sr_instance *sr, uint8_t *packet,
                              unsigned int len, char *interface)
{
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
    return;
  }

  sr_arp_hdr_t *arp = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  if (ntohs(arp->ar_hrd) != arp_hrd_ethernet ||
      ntohs(arp->ar_pro) != ethertype_ip) {
    return;
  }

  struct sr_if *recv_iface = sr_get_interface(sr, interface);
  if (!recv_iface) {
    return;
  }

  uint16_t op = ntohs(arp->ar_op);

  if (op == arp_op_request) {
    /* only answer if the request targets the receiving interface's IP. */
    if (arp->ar_tip == recv_iface->ip) {
      send_arp_reply(sr, arp, recv_iface);
    }
  } else if (op == arp_op_reply) {
    /* sr_arpcache_insert removes any matching request from the queue and
     * returns it; we drain the queued packets and discard the request.
     * the cache side-effect is intentionally unused (project 2a does not
     * cache resolutions; route_and_send always re-sends an ARP request). */
    struct sr_arpreq *req = sr_arpcache_insert(&sr->cache,
                                               arp->ar_sha,
                                               arp->ar_sip);
    if (req) {
      struct sr_packet *pkt;
      for (pkt = req->packets; pkt != NULL; pkt = pkt->next) {
        if (pkt->len < sizeof(sr_ethernet_hdr_t)) continue;
        sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)pkt->buf;
        struct sr_if *out_iface = sr_get_interface(sr, pkt->iface);
        if (out_iface) {
          memcpy(eth->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
        }
        memcpy(eth->ether_dhost, arp->ar_sha, ETHER_ADDR_LEN);
        sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
      }
      sr_arpreq_destroy(&sr->cache, req);
    }
  }
}

static void send_arp_reply(struct sr_instance *sr, sr_arp_hdr_t *req_arp,
                           struct sr_if *iface)
{
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *buf = (uint8_t *)calloc(1, len);
  if (!buf) return;

  sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)buf;
  memcpy(eth->ether_dhost, req_arp->ar_sha, ETHER_ADDR_LEN);
  memcpy(eth->ether_shost, iface->addr, ETHER_ADDR_LEN);
  eth->ether_type = htons(ethertype_arp);

  sr_arp_hdr_t *arp = (sr_arp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
  arp->ar_hrd = htons(arp_hrd_ethernet);
  arp->ar_pro = htons(ethertype_ip);
  arp->ar_hln = ETHER_ADDR_LEN;
  arp->ar_pln = 4;
  arp->ar_op  = htons(arp_op_reply);
  memcpy(arp->ar_sha, iface->addr, ETHER_ADDR_LEN);
  arp->ar_sip = iface->ip;
  memcpy(arp->ar_tha, req_arp->ar_sha, ETHER_ADDR_LEN);
  arp->ar_tip = req_arp->ar_sip;

  sr_send_packet(sr, buf, len, iface->name);
  free(buf);
}

static void send_arp_request(struct sr_instance *sr, uint32_t target_ip_nbo,
                             const char *iface_name)
{
  struct sr_if *iface = sr_get_interface(sr, iface_name);
  if (!iface) return;

  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *buf = (uint8_t *)calloc(1, len);
  if (!buf) return;

  sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)buf;
  memset(eth->ether_dhost, 0xff, ETHER_ADDR_LEN);
  memcpy(eth->ether_shost, iface->addr, ETHER_ADDR_LEN);
  eth->ether_type = htons(ethertype_arp);

  sr_arp_hdr_t *arp = (sr_arp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
  arp->ar_hrd = htons(arp_hrd_ethernet);
  arp->ar_pro = htons(ethertype_ip);
  arp->ar_hln = ETHER_ADDR_LEN;
  arp->ar_pln = 4;
  arp->ar_op  = htons(arp_op_request);
  memcpy(arp->ar_sha, iface->addr, ETHER_ADDR_LEN);
  arp->ar_sip = iface->ip;
  memset(arp->ar_tha, 0, ETHER_ADDR_LEN);
  arp->ar_tip = target_ip_nbo;

  sr_send_packet(sr, buf, len, iface->name);
  free(buf);
}

static void handle_ip_packet(struct sr_instance *sr, uint8_t *packet,
                             unsigned int len, char *interface)
{
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    return;
  }

  sr_ip_hdr_t *ip = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  unsigned int ip_hdr_len = ip->ip_hl * 4;
  if (ip_hdr_len < sizeof(sr_ip_hdr_t)) {
    return;
  }
  if (len < sizeof(sr_ethernet_hdr_t) + ip_hdr_len) {
    return;
  }
  if (ntohs(ip->ip_len) < ip_hdr_len) {
    return;
  }

  /* IP checksum is computed over the IP header only. */
  uint16_t recv_sum = ip->ip_sum;
  ip->ip_sum = 0;
  uint16_t calc_sum = cksum(ip, ip_hdr_len);
  ip->ip_sum = recv_sum;
  if (recv_sum != calc_sum) {
    return;
  }

  /* destined for one of our interfaces: reply to ICMP echo, drop the rest. */
  struct sr_if *for_iface = find_iface_for_ip(sr, ip->ip_dst);
  if (for_iface) {
    if (ip->ip_p == ip_protocol_icmp) {
      unsigned int icmp_off = sizeof(sr_ethernet_hdr_t) + ip_hdr_len;
      if (len < icmp_off + sizeof(sr_icmp_t08_hdr_t)) {
        return;
      }
      sr_icmp_t08_hdr_t *icmp = (sr_icmp_t08_hdr_t *)(packet + icmp_off);
      if (icmp->icmp_type == 8) {
        unsigned int icmp_len = len - icmp_off;
        uint16_t orig = icmp->icmp_sum;
        icmp->icmp_sum = 0;
        uint16_t c = cksum(icmp, icmp_len);
        icmp->icmp_sum = orig;
        if (orig != c) {
          return;
        }
        send_icmp_echo_reply(sr, packet, len);
      }
    }
    return;
  }

  /* TTL would hit zero on the next hop -> Time Exceeded back to source. */
  if (ip->ip_ttl <= 1) {
    struct sr_if *in_iface = sr_get_interface(sr, interface);
    uint32_t src = in_iface ? in_iface->ip : 0;
    send_icmp_error(sr, 11, 0, packet, len, src);
    return;
  }

  /* private copy: decrement TTL, recompute checksum, then forward. */
  uint8_t *frame = (uint8_t *)malloc(len);
  if (!frame) return;
  memcpy(frame, packet, len);
  sr_ip_hdr_t *new_ip = (sr_ip_hdr_t *)(frame + sizeof(sr_ethernet_hdr_t));
  new_ip->ip_ttl--;
  new_ip->ip_sum = 0;
  new_ip->ip_sum = cksum(new_ip, ip_hdr_len);

  int rc = route_and_send(sr, frame, len);
  if (rc < 0) {
    struct sr_if *in_iface = sr_get_interface(sr, interface);
    uint32_t src = in_iface ? in_iface->ip : 0;
    send_icmp_error(sr, 3, 0, packet, len, src);
  }
  free(frame);
}

static void send_icmp_echo_reply(struct sr_instance *sr, uint8_t *orig,
                                 unsigned int len)
{
  uint8_t *buf = (uint8_t *)malloc(len);
  if (!buf) return;
  memcpy(buf, orig, len);

  sr_ip_hdr_t *ip = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
  unsigned int ip_hdr_len = ip->ip_hl * 4;

  /* swap src/dst so the reply heads back to the sender. */
  uint32_t orig_src = ip->ip_src;
  ip->ip_src = ip->ip_dst;
  ip->ip_dst = orig_src;
  ip->ip_ttl = INIT_TTL;
  ip->ip_sum = 0;
  ip->ip_sum = cksum(ip, ip_hdr_len);

  /* echo request (type 8) -> echo reply (type 0); payload is unchanged. */
  sr_icmp_t08_hdr_t *icmp = (sr_icmp_t08_hdr_t *)
      (buf + sizeof(sr_ethernet_hdr_t) + ip_hdr_len);
  unsigned int icmp_len = len - sizeof(sr_ethernet_hdr_t) - ip_hdr_len;
  icmp->icmp_type = 0;
  icmp->icmp_code = 0;
  icmp->icmp_sum = 0;
  icmp->icmp_sum = cksum(icmp, icmp_len);

  route_and_send(sr, buf, len);
  free(buf);
}

static void send_icmp_error(struct sr_instance *sr, uint8_t type, uint8_t code,
                            uint8_t *orig, unsigned int orig_len,
                            uint32_t src_ip_nbo)
{
  if (orig_len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    return;
  }

  sr_ip_hdr_t *orig_ip = (sr_ip_hdr_t *)(orig + sizeof(sr_ethernet_hdr_t));

  /* if no incoming-interface IP is known, pick one via the route back. */
  if (src_ip_nbo == 0) {
    struct sr_rt *back = rt_exact_match(sr, orig_ip->ip_src);
    if (back) {
      struct sr_if *out_iface = sr_get_interface(sr, back->interface);
      if (out_iface) src_ip_nbo = out_iface->ip;
    }
  }
  if (src_ip_nbo == 0) {
    return;
  }

  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
                     sizeof(sr_icmp_t11_hdr_t);
  uint8_t *buf = (uint8_t *)calloc(1, len);
  if (!buf) return;

  sr_ip_hdr_t *ip = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t11_hdr_t *icmp = (sr_icmp_t11_hdr_t *)
      (buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  ip->ip_v   = 4;
  ip->ip_hl  = 5;
  ip->ip_tos = 0;
  ip->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
  ip->ip_id  = 0;
  ip->ip_off = htons(IP_DF);
  ip->ip_ttl = INIT_TTL;
  ip->ip_p   = ip_protocol_icmp;
  ip->ip_src = src_ip_nbo;
  ip->ip_dst = orig_ip->ip_src;
  ip->ip_sum = 0;
  ip->ip_sum = cksum(ip, sizeof(sr_ip_hdr_t));

  icmp->icmp_type = type;
  icmp->icmp_code = code;
  icmp->icmp_sum  = 0;
  icmp->unused    = 0;
  /* RFC 792: ICMP error payload is original IP header + first 8 bytes. */
  memcpy(icmp->data, orig_ip, ICMP_DATA_SIZE);
  icmp->icmp_sum = cksum(icmp, sizeof(sr_icmp_t11_hdr_t));

  route_and_send(sr, buf, len);
  free(buf);
}

/* per project 2a: exact-match route lookup, no cache, ARP every packet.
 * queues the frame on the per-next-hop arp request and triggers a send.
 * returns -1 if no matching route exists. */
static int route_and_send(struct sr_instance *sr, uint8_t *frame,
                          unsigned int len)
{
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    return -1;
  }

  sr_ip_hdr_t *ip = (sr_ip_hdr_t *)(frame + sizeof(sr_ethernet_hdr_t));
  struct sr_rt *rt = rt_exact_match(sr, ip->ip_dst);
  if (!rt) {
    return -1;
  }

  struct sr_if *out_iface = sr_get_interface(sr, rt->interface);
  if (!out_iface) {
    return -1;
  }

  uint32_t next_hop = rt->gw.s_addr;
  if (next_hop == 0) {
    next_hop = ip->ip_dst;
  }

  sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)frame;
  memcpy(eth->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
  eth->ether_type = htons(ethertype_ip);

  struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, next_hop,
                                               frame, len, out_iface->name);
  handle_arpreq(sr, req);
  return 0;
}

/* project 2a: forward only on exact destination-IP match. */
static struct sr_rt *rt_exact_match(struct sr_instance *sr, uint32_t ip_nbo)
{
  struct sr_rt *rt;
  for (rt = sr->routing_table; rt != NULL; rt = rt->next) {
    if (rt->dest.s_addr == ip_nbo) {
      return rt;
    }
  }
  return NULL;
}

static struct sr_if *find_iface_for_ip(struct sr_instance *sr, uint32_t ip_nbo)
{
  struct sr_if *i;
  for (i = sr->if_list; i != NULL; i = i->next) {
    if (i->ip == ip_nbo) {
      return i;
    }
  }
  return NULL;
}

/* arp retry / timeout; called from sr_arpcache_sweepreqs once per second
 * and from route_and_send when a new packet is queued. */
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req)
{
  if (!req) return;

  time_t now = time(NULL);
  if (difftime(now, req->sent) < 1.0) {
    return;
  }

  if (req->times_sent >= 5) {
    /* give up: host unreachable back to each queued sender. */
    struct sr_packet *pkt;
    for (pkt = req->packets; pkt != NULL; pkt = pkt->next) {
      if (pkt->len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        continue;
      }
      send_icmp_error(sr, 3, 1, pkt->buf, pkt->len, 0);
    }
    sr_arpreq_destroy(&sr->cache, req);
    return;
  }

  /* all queued packets share the same next hop, hence the same outgoing
   * interface, so the first packet's iface is authoritative. */
  const char *iface_name = req->packets ? req->packets->iface : NULL;
  if (iface_name) {
    send_arp_request(sr, req->ip, iface_name);
  }
  req->sent = now;
  req->times_sent++;
}
