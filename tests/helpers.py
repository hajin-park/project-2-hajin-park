"""
Shared helpers for the CSE 123 router test suite.

These utilities build on top of the matchers in base.py and are used by the
ARP, ping, forwarding, and error test modules. Nothing here defines a
TestCase, so the unittest discovery pattern (test*.py) ignores this file.
"""
import re
import warnings

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from scapy.all import ARP, ICMP, IP


def ping_received(output):
    """Return True if `ping` cmd output reports at least one reply.

    Tolerates both "1 received" and "1 packets received" summary formats."""
    m = re.search(r"(\d+) (?:packets )?received", output)
    return bool(m) and int(m.group(1)) >= 1


def arp_off(node):
    """Disable kernel ARP on a node's default interface so the test (or no
    one) controls ARP replies for that host."""
    intf = node["m"].defaultIntf().name
    node["m"].cmd("ip link set %s arp off" % intf)


def arp_on(node):
    intf = node["m"].defaultIntf().name
    node["m"].cmd("ip link set %s arp on" % intf)


def is_arp_reply_from(pkt, ip, mac=None):
    """True if pkt is an ARP reply (is-at) advertising `ip` (optionally mac)."""
    if ARP not in pkt:
        return False
    arp = pkt[ARP]
    if arp.op != 2 or arp.psrc != ip:
        return False
    if mac is not None and arp.hwsrc.lower() != mac.lower():
        return False
    return True


def is_arp_request_for(pkt, ip):
    """True if pkt is an ARP request (who-has) for `ip`."""
    if ARP not in pkt:
        return False
    arp = pkt[ARP]
    return arp.op == 1 and arp.pdst == ip


def icmp_matches(pkt, itype, code=None):
    """True if pkt carries an ICMP message of the given type (and code)."""
    if ICMP not in pkt:
        return False
    if pkt[ICMP].type != itype:
        return False
    if code is not None and pkt[ICMP].code != code:
        return False
    return True


def has_ip_id(pkt, ip_id):
    """True if pkt is an IP packet carrying the given identification field."""
    return IP in pkt and pkt[IP].id == ip_id


def count(pkts, pred):
    """Count packets matching pred. `pkts` is the list of (pkt, idx) tuples
    returned by CSE123TestBase.expectPackets."""
    return sum(1 for p in pkts if pred(p[0]))
