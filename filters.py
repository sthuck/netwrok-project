from typing import Dict
from socket import inet_ntoa, inet_aton
import dpkt
import ipaddress

from get_device_ip import get_device_ip


def filter_packets_only_from_dns():
    """
    Filter packets where we src or dest ip address didn't come from a dns query
    (Seems like this doesn't really work well, as in many pcaps many packets don't fit this criteria. Presumably pcap capture started after initial dns queries)
    :param ip_to_name:
    :return:
    """
    def filter_fn_factory(pcap: str, ip_to_name: Dict[str, str]):
        whitelist_ips = set(ip_to_name.keys())

        def filter_fn(ip_packet: dpkt.ip.IP):
            src_ip = inet_ntoa(ip_packet.src)
            dest_ip = inet_ntoa(ip_packet.dst)
            if src_ip in whitelist_ips or dest_ip in whitelist_ips:
                return True
        return filter_fn
    return filter_fn_factory


def filter_packets_from_local_network(subnet = 24):
    """
    Filter packets where both src and dest are inside host_ip subent
    :param host_ip:
    :param subnet:
    :return:
    """
    def filter_fn_factory(pcap: str, ip_to_name: Dict[str, str]):
        host_ip = get_device_ip(pcap)

        host_ip_binary = int.from_bytes(inet_aton(host_ip), 'big')
        subnet_binary = host_ip_binary & ((2**subnet)-1) << (32-subnet)
        network = ipaddress.ip_network((subnet_binary, subnet))

        local_ip = ipaddress.ip_address('0.0.0.0')
        broadcast_ip = ipaddress.ip_address('255.255.255.255')

        def filter_fn(ip_packet: dpkt.ip.IP):
            src_ip = ipaddress.ip_address(ip_packet.src)
            dest_ip = ipaddress.ip_address(ip_packet.dst)
            if (src_ip in network or src_ip == local_ip) and (dest_ip in network or dest_ip == broadcast_ip):
                return False # if both packets inside host subnet - filter out packet
            return True # if outside subnet don't filter
        return filter_fn
    return filter_fn_factory
