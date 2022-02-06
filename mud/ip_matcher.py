import fnmatch
import ipaddress
import socket
from abc import ABC
from typing import Dict


class AbstractIpMatcher(ABC):
    def is_match(self, packet_ip: bytes) -> bool:
        pass


class LiteralIpMatcher(AbstractIpMatcher):
    def __init__(self, ip: str):
        self.ip = ip

    def __str__(self):
        return self.ip

    def __eq__(self, other):
        return self.ip == other.ip

    def is_match(self, packet_ip: bytes):
        return ipaddress.ip_address(socket.inet_ntoa(packet_ip)) in ipaddress.ip_network(self.ip)


class DnsIpMatcher(AbstractIpMatcher):
    def __init__(self, dns_name: str, reverse_dns: Dict[str, str]):
        self.dns_name = dns_name
        """
        Ip to dns name
        """
        self.reverse_dns = reverse_dns

    def __str__(self):
        return self.dns_name

    def __eq__(self, other):
        return self.dns_name == other.dns_name

    def is_match(self, packet_ip: bytes) -> bool:
        ip_str = socket.inet_ntoa(packet_ip)
        packet_dns_name = self.reverse_dns.get(ip_str, 'unknown ip')
        return fnmatch.fnmatch(packet_dns_name, self.dns_name)
