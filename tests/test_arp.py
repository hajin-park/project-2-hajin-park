"""
ARP behavior tests.

Verifies that the router answers ARP requests for the IP of the interface the
request arrived on, ignores requests for IPs it does not own, and does not
react to unsolicited ARP replies.
"""
from base import *
from helpers import is_arp_reply_from, count
import unittest


class TestARP(CSE123TestBase):

    def setUp(self):
        self.setUpEnvironment(rtable='rtable', build=True, debug=False)

    def tearDown(self):
        self.tearDownEnvironment()

    def _arp_request(self, node, target_ip):
        """Send a who-has from `node` for target_ip and return ARP packets
        observed on that node's link."""
        req = (Ether(src=node["mac"], dst="ff:ff:ff:ff:ff:ff") /
               ARP(op=1, hwsrc=node["mac"], psrc=node["ip"], pdst=target_ip))
        self.clearPcapBuffers()
        self.sendPacket(req, node=node["m"].name)
        return self.expectPackets(node["m"].name, type='arp', timewait_sec=1)

    def _assert_router_replies(self, node):
        arps = self._arp_request(node, node["gw"])
        replies = count(arps, lambda p: is_arp_reply_from(p, node["gw"]))
        self.assertTrue(
            replies >= 1,
            msg="No ARP reply for {} from router interface {}".format(
                node["m"].name, node["gw"]))

    def test_arp_client(self):
        # ARP to the router interface from the client.
        self._assert_router_replies(self.client)

    def test_arp_server1(self):
        # ARP to the router interface from server1.
        self._assert_router_replies(self.server1)

    def test_arp_server2(self):
        # ARP to the router interface from server2.
        self._assert_router_replies(self.server2)

    def test_negative_arp(self):
        # The router must not answer ARP for an IP it does not own, even on
        # the correct interface/subnet.
        arps = self._arp_request(self.client, "10.0.1.50")
        replies = count(arps, lambda p: is_arp_reply_from(p, "10.0.1.50"))
        self.assertEqual(
            replies, 0, msg="Router answered ARP for an IP it does not own")

    def test_unsolicited_response(self):
        # An unsolicited ARP reply must not provoke a reply and must not break
        # the router (it should still answer a subsequent legitimate request).
        self.clearPcapBuffers()
        unsolicited = (Ether(src=self.client["mac"], dst=self.client["gwmac"]) /
                       ARP(op=2, hwsrc=self.client["mac"], psrc="10.0.1.50",
                           hwdst=self.client["gwmac"], pdst=self.client["gw"]))
        self.sendPacket(unsolicited, node=self.client["m"].name)
        arps = self.expectPackets(self.client["m"].name, type='arp',
                                  timewait_sec=1)
        replies = count(arps, lambda p: is_arp_reply_from(p, self.client["gw"]))
        self.assertEqual(
            replies, 0, msg="Router replied to an unsolicited ARP response")
        self._assert_router_replies(self.client)


if __name__ == "__main__":
    unittest.main()
