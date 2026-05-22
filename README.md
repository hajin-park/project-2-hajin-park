# Project 2a: Simple Router

## Info

Name: Hajin Park

PID: A18596632

Email: hap009@ucsd.edu

## Files Changed

- `sr_router.c` — full router data path.
- `sr_router.h` — exports `handle_arpreq` so the arp sweeper can call it.
- `sr_arpcache.c` — `sr_arpcache_sweepreqs` walks the pending arp requests and calls `handle_arpreq` on each. The next 
pointer is captured up front because `handle_arpreq` may destroy the request after five failed retries.

## sr_router.c overview

`sr_handlepacket` validates the Ethernet length and dispatches on EtherType
to either `handle_arp_packet` or `handle_ip_packet`. Anything else is dropped.

### ARP (`handle_arp_packet`)

- **Request**: answered only when `ar_tip` matches the IP of the interface
  the frame arrived on; the reply is built with that interface's MAC/IP.
- **Reply**: inserted via `sr_arpcache_insert`, which detaches any pending
  request for the same IP. The queued frames are drained out the queued
  interface with both Ethernet addresses rewritten, then the request is
  destroyed.

### IP (`handle_ip_packet`)

1. Sanity-check the Ethernet/IP lengths and IP header length.
2. Verify the IP checksum (header only).
3. If `ip_dst` matches one of our interfaces and the payload is an ICMP echo
   request (type 8) with a valid checksum, reply with echo (type 0). Other
   for-us traffic (TCP/UDP, non-echo ICMP) is silently dropped.
4. Otherwise forward:
   - TTL ≤ 1 ⇒ ICMP Time Exceeded (type 11, code 0).
   - Otherwise decrement TTL, recompute the IP checksum, and call
     `route_and_send`.
   - No matching route ⇒ ICMP Destination Net Unreachable (type 3, code 0).

### Forwarding (`route_and_send` + `rt_exact_match`)

Routing uses exact destination-IP match: `rt_exact_match` walks the table
and compares `rt->dest.s_addr` to `ip_dst` directly. Every forwarded packet
goes through the ARP request path — `route_and_send` queues the frame via
`sr_arpcache_queuereq` and calls `handle_arpreq`, with no `sr_arpcache_lookup`
shortcut, so resolutions are never reused across packets.

### ICMP error generation (`send_icmp_error`)

Builds an Ethernet/IP/ICMP frame with TTL=64, DF set, and an ICMP payload of
the original IP header plus the first 8 bytes of payload (per RFC 792). If
the caller passes `src_ip_nbo == 0` (i.e. the incoming interface is unknown,
as on the ARP-timeout path), the source IP is taken from the interface on
the return route to the original sender.

### ARP retries (`handle_arpreq`)

Called from `sr_arpcache_sweepreqs` (once a second) and from `route_and_send`
on initial queueing. Sends one ARP request per second; after five attempts
with no reply, emits ICMP Destination Host Unreachable (type 3, code 1) to
every queued sender and destroys the request. The outgoing interface is
taken from the first queued packet, since all frames queued under one
request share the same next hop.
