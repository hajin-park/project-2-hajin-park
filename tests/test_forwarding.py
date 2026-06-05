"""
ARP-driven forwarding tests.

Covers ARP resolution before IP forwarding, retransmission while an ARP reply
is delayed, and ICMP Host Unreachable generation when ARP never resolves.
"""
from base import *
from helpers import is_arp_request_for, icmp_matches, has_ip_id, count, arp_off
import unittest
import random
import time


class TestARPBeforeIP(CSE123TestBase):

    def setUp(self):
        self.setUpEnvironment(rtable='rtable', build=True, debug=False)

    def tearDown(self):
        self.tearDownEnvironment()

    def test_arp_request_sent(self):
        # With an empty cache the router must ARP for the next hop before it
        # can forward the IP packet.
        self.clearPcapBuffers()
        pid = random.randint(1, 65535)
        pkt = (Ether(src=self.client["mac"], dst=self.client["gwmac"]) /
               IP(src=self.client["ip"], dst=self.server1["ip"], id=pid) /
               UDP(sport=4000, dport=5000) / b"hello")
        self.sendPacket(pkt, node=self.client["m"].name)
        pkts = self.expectPackets(self.server1["m"].name, type='any',
                                  timewait_sec=2)
        self.assertTrue(
            count(pkts, lambda p: is_arp_request_for(p, self.server1["ip"])) >= 1,
            msg="Router did not ARP for the next hop before forwarding")
        self.assertTrue(
            count(pkts, lambda p: has_ip_id(p, pid) and UDP in p) >= 1,
            msg="Router did not forward the UDP packet to server1")

    def test_payload_intact(self):
        # The forwarded packet must preserve its payload and decrement TTL.
        self.clearPcapBuffers()
        pid = random.randint(1, 65535)
        payload = bytes(bytearray(range(60)))
        pkt = (Ether(src=self.client["mac"], dst=self.client["gwmac"]) /
               IP(src=self.client["ip"], dst=self.server1["ip"], id=pid) /
               UDP(sport=4000, dport=5000) / payload)
        self.sendPacket(pkt, node=self.client["m"].name)
        pkts = self.expectPackets(self.server1["m"].name, type='udp',
                                  timewait_sec=2)
        match = [p[0] for p in pkts if has_ip_id(p[0], pid)]
        self.assertTrue(len(match) >= 1, msg="UDP packet was not forwarded")
        fwd = match[0]
        self.assertEqual(bytes(fwd[UDP].payload), payload,
                         msg="Forwarded payload was altered")
        self.assertEqual(fwd[IP].ttl, pkt[IP].ttl - 1,
                         msg="TTL was not decremented on forward")


class TestDelayARP(CSE123TestBase):

    def setUp(self):
        self.setUpEnvironment(rtable='rtable', build=True, debug=False)

    def tearDown(self):
        self.tearDownEnvironment()

    def test_delayed_arp_reply(self):
        # Silence server1's kernel ARP so the test controls reply timing.
        arp_off(self.server1)
        self.clearPcapBuffers()
        pid = random.randint(1, 65535)
        echo = (Ether(src=self.client["mac"], dst=self.client["gwmac"]) /
                IP(src=self.client["ip"], dst=self.server1["ip"], id=pid) /
                ICMP(type=8))
        self.sendPacket(echo, node=self.client["m"].name)
        # Let the router send a few unanswered ARP requests.
        time.sleep(2.5)
        reqs = self.expectPackets(self.server1["m"].name, type='arp',
                                  timewait_sec=0.1)
        self.assertTrue(
            count(reqs, lambda p: is_arp_request_for(p, self.server1["ip"])) >= 1,
            msg="Router did not retry ARP while waiting for a reply")
        # Now answer the ARP; the queued echo must be flushed to server1.
        reply = (Ether(src=self.server1["mac"], dst=self.server1["gwmac"]) /
                 ARP(op=2, hwsrc=self.server1["mac"], psrc=self.server1["ip"],
                     hwdst=self.server1["gwmac"], pdst=self.server1["gw"]))
        self.clearPcapBuffers()
        self.sendPacket(reply, node=self.server1["m"].name)
        pkts = self.expectPackets(self.server1["m"].name, type='icmp',
                                  timewait_sec=2)
        self.assertTrue(
            count(pkts, lambda p: has_ip_id(p, pid) and icmp_matches(p, 8)) >= 1,
            msg="Queued packet was not forwarded after the delayed ARP reply")


class TestDropOnNoARP(CSE123TestBase):

    def setUp(self):
        self.setUpEnvironment(rtable='rtable', build=True, debug=False)

    def tearDown(self):
        self.tearDownEnvironment()

    def test_host_unreachable(self):
        # server1 never answers ARP, so the next hop is unresolvable; after the
        # retry budget is exhausted the router must reply Host Unreachable.
        arp_off(self.server1)
        self.clearPcapBuffers()
        pid = random.randint(1, 65535)
        echo = (Ether(src=self.client["mac"], dst=self.client["gwmac"]) /
                IP(src=self.client["ip"], dst=self.server1["ip"], id=pid) /
                ICMP(type=8))
        self.sendPacket(echo, node=self.client["m"].name)
        # ~5 ARP retries at 1/s before giving up.
        icmps = self.expectPackets(self.client["m"].name, type='icmp',
                                   timewait_sec=8)
        self.assertTrue(
            count(icmps, lambda p: icmp_matches(p, 3, 1)) >= 1,
            msg="Router did not send Host Unreachable after ARP failures")


if __name__ == "__main__":
    unittest.main()
