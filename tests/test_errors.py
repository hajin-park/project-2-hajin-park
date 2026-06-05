"""
Error-path tests.

Covers silent drops on bad checksums, Destination Net Unreachable for unknown
networks, and routing-table edge cases (missing host vs. subnet route) that
exercise Longest Prefix Match and Host/Net Unreachable generation.
"""
from base import *
from helpers import icmp_matches, has_ip_id, count
import unittest
import random


class TestBadICMP(CSE123TestBase):

    def setUp(self):
        self.setUpEnvironment(rtable='rtable', build=True, debug=False)

    def tearDown(self):
        self.tearDownEnvironment()

    def test_bad_ip_checksum(self):
        # A corrupt IP checksum must cause a silent drop: no forward, no error.
        self.clearPcapBuffers()
        pid = random.randint(1, 65535)
        pkt = (Ether(src=self.client["mac"], dst=self.client["gwmac"]) /
               IP(src=self.client["ip"], dst=self.server1["ip"], id=pid,
                  chksum=0x1234) / ICMP(type=8))
        self.sendPacket(pkt, node=self.client["m"].name)
        fwd = self.expectPackets(self.server1["m"].name, type='icmp',
                                 timewait_sec=1)
        self.assertEqual(
            count(fwd, lambda p: has_ip_id(p, pid)), 0,
            msg="Router forwarded a packet with a bad IP checksum")
        errs = self.expectPackets(self.client["m"].name, type='icmp',
                                  timewait_sec=0.1)
        self.assertEqual(
            count(errs, lambda p: icmp_matches(p, 3) or icmp_matches(p, 11)), 0,
            msg="Router generated an ICMP error for a bad-checksum packet")

    def test_bad_icmp_checksum(self):
        # Echo to the router with a corrupt ICMP checksum -> no echo reply.
        self.clearPcapBuffers()
        pid = random.randint(1, 65535)
        pkt = (Ether(src=self.client["mac"], dst=self.client["gwmac"]) /
               IP(src=self.client["ip"], dst=self.client["gw"], id=pid) /
               ICMP(type=8, chksum=0x4321))
        self.sendPacket(pkt, node=self.client["m"].name)
        icmps = self.expectPackets(self.client["m"].name, type='icmp',
                                   timewait_sec=1)
        self.assertEqual(
            count(icmps, lambda p: icmp_matches(p, 0)), 0,
            msg="Router replied to an echo with a bad ICMP checksum")

    def test_net_unreachable(self):
        # No route to 8.8.8.8 -> Destination Net Unreachable (type 3, code 0).
        self.clearPcapBuffers()
        pid = random.randint(1, 65535)
        pkt = (Ether(src=self.client["mac"], dst=self.client["gwmac"]) /
               IP(src=self.client["ip"], dst="8.8.8.8", id=pid) / ICMP(type=8))
        self.sendPacket(pkt, node=self.client["m"].name)
        icmps = self.expectPackets(self.client["m"].name, type='icmp',
                                   timewait_sec=2)
        self.assertTrue(
            count(icmps, lambda p: icmp_matches(p, 3, 0)) >= 1,
            msg="Router did not send Net Unreachable for an unknown network")


class TestBadRTableHost(CSE123TestBase):

    def setUp(self):
        # Routes 172.64.3.11/32 instead of the real server2 (.10).
        self.setUpEnvironment(rtable='bad_rtable_host', build=True, debug=False)

    def tearDown(self):
        self.tearDownEnvironment()

    def test_net_unreachable_real_host(self):
        # The real server2 IP (.10) matches no route -> Net Unreachable.
        self.clearPcapBuffers()
        pid = random.randint(1, 65535)
        pkt = (Ether(src=self.client["mac"], dst=self.client["gwmac"]) /
               IP(src=self.client["ip"], dst=self.server2["ip"], id=pid) /
               ICMP(type=8))
        self.sendPacket(pkt, node=self.client["m"].name)
        icmps = self.expectPackets(self.client["m"].name, type='icmp',
                                   timewait_sec=2)
        self.assertTrue(
            count(icmps, lambda p: icmp_matches(p, 3, 0)) >= 1,
            msg="Router did not send Net Unreachable for an unrouteable host")

    def test_host_unreachable_phantom(self):
        # 172.64.3.11 is routed but unowned -> ARP fails -> Host Unreachable.
        self.clearPcapBuffers()
        pid = random.randint(1, 65535)
        pkt = (Ether(src=self.client["mac"], dst=self.client["gwmac"]) /
               IP(src=self.client["ip"], dst="172.64.3.11", id=pid) /
               ICMP(type=8))
        self.sendPacket(pkt, node=self.client["m"].name)
        icmps = self.expectPackets(self.client["m"].name, type='icmp',
                                   timewait_sec=8)
        self.assertTrue(
            count(icmps, lambda p: icmp_matches(p, 3, 1)) >= 1,
            msg="Router did not send Host Unreachable for an unowned routed host")


class TestBadRTableEntry(CSE123TestBase):

    def setUp(self):
        # Routes 172.64.3.0/24 via gateway 172.64.3.10 (a subnet route).
        self.setUpEnvironment(rtable='bad_rtable_entry', build=True, debug=False)

    def tearDown(self):
        self.tearDownEnvironment()

    def test_lpm_subnet_forwarding(self):
        # Longest Prefix Match must forward server2's traffic via the /24 route.
        self.clearPcapBuffers()
        pid = random.randint(1, 65535)
        pkt = (Ether(src=self.client["mac"], dst=self.client["gwmac"]) /
               IP(src=self.client["ip"], dst=self.server2["ip"], id=pid) /
               ICMP(type=8))
        self.sendPacket(pkt, node=self.client["m"].name)
        pkts = self.expectPackets(self.server2["m"].name, type='icmp',
                                  timewait_sec=2)
        self.assertTrue(
            count(pkts, lambda p: has_ip_id(p, pid) and icmp_matches(p, 8)) >= 1,
            msg="LPM did not forward through the subnet route to server2")


if __name__ == "__main__":
    unittest.main()
