import dpkt
from mud import ParsedMudFile
from typing import List


def iterate_pcap(filename, configs: ParsedMudFile, filter_fn=lambda x: True):
    packets_not_in_mud: List[dpkt.ip.IP] = []
    with open(filename, 'rb') as f:
        total_bandwidth = 0
        for timestamp, buffer in dpkt.pcapng.Reader(f):
            eth_packet = dpkt.ethernet.Ethernet(buffer)

            if eth_packet.type != dpkt.ethernet.ETH_TYPE_IP:
                continue
            if not filter_fn(eth_packet.data):
                continue

            total_bandwidth += eth_packet.data.len
            found_in_mud_rule = False
            for config, data in configs.items():
                if config.verify(eth_packet.data):
                    found_in_mud_rule = True
                    data.packets += 1
                    data.size += eth_packet.data.len
                    if config.is_new_connection(eth_packet.data):
                        data.connections += 1
                    break

            if not found_in_mud_rule:
                p = eth_packet.data
                if p.p == 6 or p.p == 17:
                    # if p.data.sport not in [80, 443, 123] and p.data.dport not in [80, 443, 123]:
                    packets_not_in_mud.append(eth_packet.data)
                # raise Exception('traffic in pcap doesnt match rules') # review this
    return configs, total_bandwidth, packets_not_in_mud
