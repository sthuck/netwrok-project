import fnmatch
import ipaddress
import socket
from abc import ABC
from typing import Dict, List


class AbstractIpMatcher(ABC):
    def is_match(self, packet_ip: bytes) -> bool:
        """
        Given ip address (in binary/btyes), return True if matches the rule passed in the constructor
        :param packet_ip:
        :return:
        """
        pass


class LiteralIpMatcher(AbstractIpMatcher):
    """
    a class that can match an ip address to an ip subnet in cidr notation
    """
    def __init__(self, ip: str):
        """
        :param ip: cidr notation of subnet
        """
        self.ip = ip

    def __str__(self):
        return self.ip

    def __eq__(self, other):
        return self.ip == other.ip

    def is_match(self, packet_ip: bytes):
        return ipaddress.ip_address(socket.inet_ntoa(packet_ip)) in ipaddress.ip_network(self.ip)


class DnsIpMatcher(AbstractIpMatcher):
    """
    This class can help match an ip address to a dns name
    """
    def __init__(self, dns_name: str, reverse_dns: Dict[str, List[str]]):
        """

        :param dns_name: the dns name to match on, can accept wild cards
        :param reverse_dns: a dictionary that maps between ip addresses and dns names
        """

        self.dns_name = dns_name
        self.reverse_dns = reverse_dns

    def __str__(self):
        return self.dns_name

    def __eq__(self, other):
        return self.dns_name == other.dns_name

    def is_match(self, packet_ip: bytes) -> bool:
        ip_str = socket.inet_ntoa(packet_ip)
        packet_dns_name = self.reverse_dns.get(ip_str, ['unknown ip'])
        return any(fnmatch.fnmatch(host, self.dns_name) for host in packet_dns_name)
