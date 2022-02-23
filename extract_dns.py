import dpkt
from typing import Dict, List, Set
import socket

from filename_helpers import get_pcap_dns


def extract_dns(device: str, country: str):
    filename = get_pcap_dns(device, country)
    name_to_ip: Dict[str, Set[str]] = {}
    ip_to_name: Dict[str, Set[str]] = {}
    cnames: Dict[str, List[str]] = {} # key is known host name, value is requested names
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
                        if hasattr(rr, 'ip'):
                            ip = socket.inet_ntoa(rr.ip)
                            ips = name_to_ip.get(name, set())
                            name_to_ip[name] = ips.union(ip)

                            name_to_ip[name] = ips
                            current_names = ip_to_name.get(ip, set())
                            ip_to_name[ip] = current_names.union({name})

                        if hasattr(rr, 'ip6'):
                            ip = socket.inet_ntop(socket.AF_INET6, rr.ip6)
                            ips = name_to_ip.get(name, set())
                            name_to_ip[name] = ips.union(ip)

                            name_to_ip[name] = ips
                            current_names = ip_to_name.get(ip, set())
                            ip_to_name[ip] = current_names.union({name})

                        elif hasattr(rr, 'cname'):
                            cname = rr.cname
                            current_aliases = cnames.get(cname, [])
                            cnames[cname] = current_aliases + [name]

    # using loop because we might try to resolve a cname when we don't know the original name yet
    cnames_to_resolve = cnames
    iterations_without_change = 0

    while len(cnames_to_resolve) and iterations_without_change < 100:
        for name, aliases in cnames_to_resolve.items():  # key is known host name, value is requested name
            if name in name_to_ip:
                iterations_without_change = 0
                for alias in aliases:
                    ips = name_to_ip.get(name, set())
                    name_to_ip[alias] = ips

                    for ip in ips:
                        names = ip_to_name[ip]
                        ip_to_name[ip] = names.union({alias})
        iterations_without_change = iterations_without_change + 1

        next_cnames_to_resolve = {}
        for name, aliases in cnames_to_resolve.items():
            unresolved_aliases = [alias for alias in aliases if alias not in name_to_ip]
            if len(unresolved_aliases):
                next_cnames_to_resolve[name] = unresolved_aliases
        cnames_to_resolve = next_cnames_to_resolve

    return name_to_ip, ip_to_name
