import socket
import dpkt
from typing import Dict

""" 
Ugly hack file, saving global state here 
but needed because we need to track connection in both ways 
And this is the quickest way to do so 
Not used for TCP where we can track connections on our own
"""


def ip_packet_to_key(ip_packet: dpkt.ip.IP):
    ip_src = socket.inet_ntoa(ip_packet.src)
    ip_dst = socket.inet_ntoa(ip_packet.dst)

    if ip_packet.p == dpkt.ip.IP_PROTO_TCP:
        tcp_packet: dpkt.tcp.TCP = ip_packet.data
        key = f'TCP,{ip_src}:{tcp_packet.sport},{ip_dst}:{tcp_packet.dport}'
        reverse_key = f'TCP,{ip_dst}:{tcp_packet.dport},{ip_src}:{tcp_packet.sport}'

    elif ip_packet.p == dpkt.ip.IP_PROTO_UDP:
        udp_packet: dpkt.udp.UDP = ip_packet.data
        key = f'UDP,{ip_src}:{udp_packet.sport},{ip_dst}:{udp_packet.dport}'
        reverse_key = f'UDP,{ip_dst}:{udp_packet.dport},{ip_src}:{udp_packet.sport}'
    else:
        key = f'protocol:{ip_packet.p},{ip_src},{ip_dst}'
        reverse_key = f'protocol:{ip_packet.p},{ip_dst},{ip_src}'

    return key, reverse_key


class ConnectionTracker:
    packet_counter: Dict[str, int] = {}

    def reset(self):
        self.packet_counter = {}

    def count(self, packet: dpkt.ip.IP):
        key, _ = ip_packet_to_key(packet)
        current = self.packet_counter.get(key, 0)
        self.packet_counter.update([(key, current + 1)])

    def get_count_in_connection(self, packet: dpkt.ip.IP):
        key, reverse_key = ip_packet_to_key(packet)
        current = self.packet_counter.get(key, 0)
        current_reverse = self.packet_counter.get(reverse_key, 0)

        return current + current_reverse


globalConnectionTracker = ConnectionTracker()
