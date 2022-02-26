import ipaddress
import os
from extract_dns import extract_dns
from filename_helpers import get_pcap, get_mud
from mud import parse_mud_file, CatchAllRule, PacketTracker
from iterate_pcap import iterate_pcap
import pandas as pd
from typing import Dict, List
from socket import inet_ntoa, inet_aton
import dpkt
from filters import filter_packets_from_local_network, filter_packets_only_from_dns
from get_device_ip import get_device_ip
from mud.global_connection_tracker import globalConnectionTracker

devices = [
    "appletv_merged",
    "blink-camera_merged",
    "blink-security-hub_merged",
    "echodot_merged",
    "echoplus_merged",
    "echospot_merged",
    "firetv_merged",
    "google-home-mini_merged",
    # "insteon-hub_merged",
    "lightify-hub_merged",
    "magichome-strip_merged",
    "nest-tstat_merged",
    "ring-doorbell_merged",
    "roku-tv_merged",
    "samsungtv-wired_merged",
    "sengled-hub_merged",
    "smartthings-hub_merged",
    "t-philips-hub_merged",
    "tplink-bulb_merged",
    "tplink-plug_merged",
    "t-wemo-plug_merged",
    "wansview-cam-wired_merged",
    "xiaomi-cleaner_merged",
    "xiaomi-hub_merged",
    "yi-camera_merged"
]


def get_pcap_counts(device: str, country: str, filter_factory):
    pcap = get_pcap(device, country)
    mud = get_mud(device, country)
    print(f'extracting dns {device} ,{country}')
    _, ip_to_name = extract_dns(device, country)

    filter_fn = filter_factory(pcap, ip_to_name)

    configs = parse_mud_file(mud, ip_to_name)

    print(f'iterating over pcap {device}, {country}')
    iterate_pcap(pcap, configs, filter_fn=filter_fn)
    not_in_mud_counters = configs.pop(CatchAllRule())
    return configs, not_in_mud_counters


def compare_one(device: str, filter_factory, count_traffic_not_in_mud=True):
    print(f'comparing device {device}')
    counts_uk, not_in_mud_counts_uk = get_pcap_counts(device, 'uk', filter_factory)
    counts_us, not_in_mud_counts_us = get_pcap_counts(device, 'us', filter_factory)

    if not count_traffic_not_in_mud:
        not_in_mud_counts_us = PacketTracker(0, 0, 0)
        not_in_mud_counts_uk = PacketTracker(0, 0, 0)

    rules_us = set(counts_us.keys())
    rules_uk = set(counts_uk.keys())

    in_both = rules_uk.intersection(rules_us)
    us_only = rules_us.difference(rules_uk)
    uk_only = rules_uk.difference(rules_us)

    """Bandwidth"""
    total_bandwidth_us = sum(t.size for t in counts_us.values()) + not_in_mud_counts_us.size
    us_identical_ace_bw = sum(t.size for (rule, t) in counts_us.items() if rule in in_both)
    us_unique_ace_bw = sum(t.size for (rule, t) in counts_us.items() if rule in us_only)

    total_bandwidth_uk = sum(t.size for t in counts_uk.values()) + not_in_mud_counts_uk.size
    uk_identical_ace_bw = sum(t.size for (rule, t) in counts_uk.items() if rule in in_both)
    uk_unique_ace_bw = sum(t.size for (rule, t) in counts_uk.items() if rule in uk_only)

    """Connection"""
    total_connection_us = sum(t.connections for t in counts_us.values()) + not_in_mud_counts_us.connections
    us_identical_ace_connections = sum(t.connections for (rule, t) in counts_us.items() if rule in in_both)
    us_unique_ace_connections = sum(t.connections for (rule, t) in counts_us.items() if rule in us_only)

    total_connection_uk = sum(t.connections for t in counts_uk.values()) + not_in_mud_counts_uk.connections
    uk_identical_ace_connections = sum(t.connections for (rule, t) in counts_uk.items() if rule in in_both)
    uk_unique_ace_connections = sum(t.connections for (rule, t) in counts_uk.items() if rule in uk_only)

    """ACE"""
    total_ace_us = len(rules_us)
    total_ace_uk = len(rules_uk)

    """Percentages"""
    us_identical_ace_percent = len(in_both) / total_ace_us
    uk_identical_ace_percent = len(in_both) / total_ace_uk

    us_identical_ace_bw_percent = us_identical_ace_bw / total_bandwidth_us
    uk_identical_ace_bw_percent = uk_identical_ace_bw / total_bandwidth_uk

    us_identical_ace_connections_percent = us_identical_ace_connections / total_connection_us
    uk_identical_ace_connections_percent = uk_identical_ace_connections / total_connection_uk

    us_unique_ace_percent = len(us_only) / total_ace_us
    uk_unique_ace_percent = len(uk_only) / total_ace_uk

    us_unique_ace_bw_percent = us_unique_ace_bw / total_bandwidth_us
    uk_unique_ace_bw_percent = uk_unique_ace_bw / total_bandwidth_uk

    us_unique_ace_connections_percent = us_unique_ace_connections / total_connection_us
    uk_unique_ace_connections_percent = uk_unique_ace_connections / total_connection_uk

    return pd.DataFrame(data={
        'us': [us_identical_ace_percent, us_identical_ace_bw_percent, us_identical_ace_connections_percent,
               us_unique_ace_percent, us_unique_ace_bw_percent, us_unique_ace_connections_percent],
        'uk': [uk_identical_ace_percent, uk_identical_ace_bw_percent, uk_identical_ace_connections_percent,
               uk_unique_ace_percent, uk_unique_ace_bw_percent, uk_unique_ace_connections_percent]},
        index=['Identical ACEs (%)', 'Identical ACEs BW (%)', 'Identical ACEs connections (%)',
               'Unique ACEs (%)', 'Unique ACEs BW(%)', 'Unique ACEs connections (%)'])


def check_files_exist():
    for device in devices:
        for country in ['us', 'uk']:
            for fn in [get_mud, get_pcap]:
                if not os.path.isfile(fn(device, country)):
                    print(f'cant find file {fn(device, country)}')


if __name__ == '__main__':
    for device in devices:
        globalConnectionTracker.reset()
        COUNT_NOT_IN_MUD = False

        # filter_factory = filter_packets_only_from_dns() # some outside traffic gets filtered, because some destinations dont have a matching dns query in pcap
        filter_factory = filter_packets_from_local_network(subnet=24)

        df = compare_one(device, filter_factory, count_traffic_not_in_mud=COUNT_NOT_IN_MUD)
        print(df)
