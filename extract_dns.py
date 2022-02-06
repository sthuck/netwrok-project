import dpkt
from typing import Dict, List
import socket


def extract_dns(filename):
    name_to_ip: Dict[str, List[str]] = {}
    ip_to_name: Dict[str, str] = {}

    with open(filename, 'rb') as f:
        for timestamp, buffer in dpkt.pcapng.Reader(f):
            eth_packet = dpkt.ethernet.Ethernet(buffer)
            if eth_packet.type != dpkt.ethernet.ETH_TYPE_IP:
                continue
            ip_packet: dpkt.ip.IP = eth_packet.data
            if ip_packet.p == dpkt.ip.IP_PROTO_UDP:
                udp_packet: dpkt.udp.UDP = ip_packet.data
                if udp_packet.sport == 53:
                    dns = dpkt.dns.DNS()
                    dns.unpack(udp_packet.data)
                    for result in dns.an:
                        rr: dpkt.dns.DNS.RR = result
                        name = rr.name
                        if hasattr(rr, 'ip'): # TODO: support more complicated dns (cname) here
                            ip = socket.inet_ntoa(rr.ip)
                            ips = name_to_ip.get(name, [])
                            ips.append(ip)

                            name_to_ip[name] = ips
                            ip_to_name[ip] = name
    return name_to_ip, ip_to_name
