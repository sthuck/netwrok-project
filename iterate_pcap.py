import dpkt
from mud import ParsedMudFile
from typing import List


def iterate_pcap(filename, configs: ParsedMudFile, filter_fn=lambda x: True):

    with open(filename, 'rb') as f:
        for timestamp, buffer in dpkt.pcapng.Reader(f):
            eth_packet = dpkt.ethernet.Ethernet(buffer)

            if eth_packet.type != dpkt.ethernet.ETH_TYPE_IP:
                continue
            if not filter_fn(eth_packet.data):
                continue

            for config, data in configs.items():
                if config.verify(eth_packet.data):
                    data.packets += 1
                    data.size += eth_packet.data.len
                    if config.is_new_connection(eth_packet.data):
                        data.connections += 1
                    break

    return configs
