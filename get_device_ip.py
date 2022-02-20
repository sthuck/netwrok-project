import dpkt
from typing import Dict, List
import socket


def get_device_ip(filename):
    ip_to_count: Dict[str, int] = {}

    with open(filename, 'rb') as f:
        for timestamp, buffer in dpkt.pcapng.Reader(f):
            eth_packet = dpkt.ethernet.Ethernet(buffer)
            if eth_packet.type != dpkt.ethernet.ETH_TYPE_IP:
                continue
            ip_packet: dpkt.ip.IP = eth_packet.data
            ip_src = socket.inet_ntoa(ip_packet.src)
            ip_dst = socket.inet_ntoa(ip_packet.dst)
            ip_to_count[ip_src] = ip_to_count.get(ip_src, 0) + 1
            ip_to_count[ip_dst] = ip_to_count.get(ip_dst, 0) + 1
    most_common_ip = max(ip_to_count.items(), key=lambda x: x[1])
    return most_common_ip[0]


if __name__ == '__main__':
    print(get_device_ip('./merged_pcaps_only/smartthings-hub_merged_us.pcapng'))