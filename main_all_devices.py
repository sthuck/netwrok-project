import os
from extract_dns import extract_dns
from mud import parse_mud_file
from iterate_pcap import iterate_pcap
import pandas as pd
from typing import Dict, List
from socket import inet_ntoa
import dpkt

devices = [
           # "appletv_merged",
           # "blink-camera_merged",
           # "blink-security-hub_merged",
           # "echodot_merged",
           # "echospot_merged",
           # "firetv_merged",
           # "google-home-mini_merged",
           # "insteon-hub_merged",
           # "lightify-hub_merged",
           # "magichome-strip_merged",
           # "nest-tstat_merged",
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
           "yi-camera_merged"]


def get_pcap(device, country):
    return f'merged_pcaps_only/{device}_{country}.pcapng'


def get_mud(device, country):
    device = device.replace('-', '_') \
        .replace('echodot', 'echo_dot') \
        .replace('echospot', 'echo_spot') \
        .replace('firetv', 'fire_tv') \
        .replace('wansview_cam_wired', 'wansview_cam')

    return f'IoT_mud_files_locations/{device}_{country}/{device}_{country}Mud.json'


def filter_packets_only_from_dns(ip_to_name: Dict[str, str]):
    whitelist_ips = set(ip_to_name.keys())

    def filter_fn(ip_packet: dpkt.ip.IP):
        src_ip = inet_ntoa(ip_packet.src)
        dest_ip = inet_ntoa(ip_packet.dst)
        if src_ip in whitelist_ips or dest_ip in whitelist_ips:
            return True
    return filter_fn


def get_pcap_counts(device: str, country: str):
    pcap = get_pcap(device, country)
    mud = get_mud(device, country)
    _, ip_to_name = extract_dns(pcap)

    configs = parse_mud_file(mud, ip_to_name)
    _, __, packets_not_in_mud = iterate_pcap(pcap, configs, filter_fn=filter_packets_only_from_dns(ip_to_name))
    print(f'device: {device}, country: {country}, packets_not_in_mud: {len(packets_not_in_mud)}')
    if len(packets_not_in_mud) > 0:
        not_in_mud = set((inet_ntoa(p.src), p.data.sport, inet_ntoa(p.dst), p.data.dport) for p in packets_not_in_mud)
        print(not_in_mud)

    return configs


def compare_one(device: str):
    print(f'comparing device {device}')
    counts_us = get_pcap_counts(device, 'us')
    counts_uk = get_pcap_counts(device, 'uk')
    rules_us = set(counts_us.keys())
    rules_uk = set(counts_uk.keys())

    in_both = rules_uk.intersection(rules_us)
    us_only = rules_us.difference(rules_uk)
    uk_only = rules_uk.difference(rules_us)

    """Bandwidth"""
    total_bandwidth_us = sum(t.size for t in counts_us.values())
    us_identical_ace_bw = sum(t.size for (rule, t) in counts_us.items() if rule in in_both)
    us_unique_ace_bw = sum(t.size for (rule, t) in counts_us.items() if rule in us_only)

    total_bandwidth_uk = sum(t.size for t in counts_uk.values())
    uk_identical_ace_bw = sum(t.size for (rule, t) in counts_uk.items() if rule in in_both)
    uk_unique_ace_bw = sum(t.size for (rule, t) in counts_uk.items() if rule in uk_only)

    """Connection"""
    total_connection_us = sum(t.connections for t in counts_us.values())
    us_identical_ace_connections = sum(t.connections for (rule, t) in counts_us.items() if rule in in_both)
    us_unique_ace_connections = sum(t.connections for (rule, t) in counts_us.items() if rule in us_only)

    total_connection_uk = sum(t.connections for t in counts_uk.values())
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
        df = compare_one(device)
        print(df)
