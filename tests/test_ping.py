"""
Ping / ICMP echo tests.

Covers end-to-end forwarding (client<->servers), echo replies for the router's
own interfaces (link-local pings), payload sizes, and TTL handling
(Time Exceeded on expiry).
"""
from base import *
from helpers import ping_received, icmp_matches, has_ip_id, count
import unittest
import random


class TestPing(CSE123TestBase):

    def setUp(self):
        self.setUpEnvironment(rtable='rtable', build=True, debug=False)

    def tearDown(self):
        self.tearDownEnvironment()

    def test_ping_client(self):
        # client -> server1 through the router.
        out = self.client["m"].cmd("ping -c 1 %s" % self.server1["ip"])
        self.assertTrue(ping_received(out), msg="client could not ping server1")

    def test_ping_server1(self):
        # server1 -> server2 through the router.
        out = self.server1["m"].cmd("ping -c 1 %s" % self.server2["ip"])
        self.assertTrue(ping_received(out),
                        msg="server1 could not ping server2")

    def test_ping_server2(self):
        # server2 -> its directly-connected (link-local) router interface.
        out = self.server2["m"].cmd("ping -c 1 %s" % self.server2["gw"])
        self.assertTrue(ping_received(out),
                        msg="server2 could not ping its router interface")

    def test_small_size(self):
        # Ping server1 with a small payload.
        out = self.client["m"].cmd("ping -c 1 -s 1 %s" % self.server1["ip"])
        self.assertTrue(ping_received(out),
                        msg="client could not ping server1 (small payload)")

    def test_large_size(self):
        # Ping server1 with a large payload.
        out = self.client["m"].cmd("ping -c 1 -s 1000 %s" % self.server1["ip"])
        self.assertTrue(ping_received(out),
                        msg="client could not ping server1 (large payload)")

    def test_ping_router_reply(self):
        # An echo request to a router interface yields an echo reply (type 0).
        self.clearPcapBuffers()
        pid = random.randint(1, 65535)
        pkt = (Ether(src=self.client["mac"], dst=self.client["gwmac"]) /
               IP(src=self.client["ip"], dst=self.client["gw"], id=pid) /
               ICMP(type=8))
        self.sendPacket(pkt, node=self.client["m"].name)
        icmps = self.expectPackets(self.client["m"].name, type='icmp',
                                   timewait_sec=2)
        replies = count(icmps, lambda p: icmp_matches(p, 0))
        self.assertTrue(
            replies >= 1,
            msg="Router did not echo-reply to a ping of its own interface")

    def test_ping_ttl_expired(self):
        # TTL=1 to a forwarded destination -> Time Exceeded (type 11, code 0).
        self.clearPcapBuffers()
        pid = random.randint(1, 65535)
        pkt = (Ether(src=self.client["mac"], dst=self.client["gwmac"]) /
               IP(src=self.client["ip"], dst=self.server1["ip"], ttl=1, id=pid) /
               ICMP(type=8))
        self.sendPacket(pkt, node=self.client["m"].name)
        icmps = self.expectPackets(self.client["m"].name, type='icmp',
                                   timewait_sec=2)
        te = count(icmps, lambda p: icmp_matches(p, 11, 0))
        self.assertTrue(
            te >= 1,
            msg="Router did not send Time Exceeded for a TTL=1 packet")
        # The expired packet must not be forwarded on to the destination.
        fwd = self.expectPackets(self.server1["m"].name, type='icmp',
                                 timewait_sec=0.1)
        self.assertEqual(
            count(fwd, lambda p: has_ip_id(p, pid)), 0,
            msg="Router forwarded a packet whose TTL had expired")


if __name__ == "__main__":
    unittest.main()
