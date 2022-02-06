import dpkt
from mud import parse_mud_file, ParsedMudFile


def iterate_pcap(filename, configs: ParsedMudFile):
    with open(filename, 'rb') as f:
        total_bandwidth = 0
        for timestamp, buffer in dpkt.pcapng.Reader(f):
            eth_packet = dpkt.ethernet.Ethernet(buffer)
            if eth_packet.type != dpkt.ethernet.ETH_TYPE_IP:
                continue
            total_bandwidth += eth_packet.data.len
            for config, data in configs.items():
                if config.verify(eth_packet.data):
                    data.packets += 1
                    data.size += eth_packet.data.len
                    if config.is_new_connection(eth_packet.data):
                        data.connections += 1
                else:
                    pass
                    # raise Exception('traffic in pcap doesnt match rules') # review this
    return configs, total_bandwidth
