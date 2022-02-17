from typing import NamedTuple, Dict, Union
import json
from .mud_rules import AbstractMudRule, MudRuleIP, MudRuleUDP, MudRuleICMP, MudRuleTCP, MudRuleIGMP
import dpkt
import socket
from dataclasses import dataclass
from .ip_matcher import LiteralIpMatcher,DnsIpMatcher, AbstractIpMatcher

@dataclass()
class PacketTracker:
    size: int
    packets: int
    connections: int


def _get_ip_addr_matcher(ip_section, reverse_dns: Dict[str, str]) -> tuple:
    """

    :param ip_section:
    :param reverse_dns:
    :return:
    """
    if 'source-ipv4-network' in ip_section:
        return LiteralIpMatcher(ip_section['source-ipv4-network']), None
    if 'ietf-acldns:src-dnsname' in ip_section:
        return DnsIpMatcher(ip_section['ietf-acldns:src-dnsname'], reverse_dns), None
    if 'ietf-acldns:dst-dnsname' in ip_section:
        return None, DnsIpMatcher(ip_section['ietf-acldns:dst-dnsname'], reverse_dns)
    if 'destination-ipv4-network' in ip_section:
        return None, LiteralIpMatcher(ip_section['destination-ipv4-network'])
    return None, None


ParsedMudFile = Dict[AbstractMudRule, PacketTracker]


def parse_mud_file(mud_file, reverse_dns: Dict[str, str], raise_on_unknown_rule = False) -> ParsedMudFile:
    configs: ParsedMudFile = {}
    with open(mud_file) as f:
        config_json = json.loads(f.read())

    for entry in config_json.get('ietf-access-control-list:access-lists', {}).get('acl', []):
        for c in entry['aces']['ace']:

            if c['matches'].get('ipv4') is None:
                continue
            src_ip_addr, dst_ip_addr = _get_ip_addr_matcher(c['matches']['ipv4'], reverse_dns)
            c_ip = MudRuleIP(c['matches']['ipv4']['protocol'], src_ip_addr, dst_ip_addr)

            if c['matches']['ipv4']['protocol'] == dpkt.ip.IP_PROTO_ICMP:
                configs[MudRuleICMP(c['matches']['icmp']['type'], c['matches']['icmp']['code'], c_ip)] = PacketTracker(
                    0, 0, 0)
            elif c['matches']['ipv4']['protocol'] == dpkt.ip.IP_PROTO_IGMP:
                configs[MudRuleIGMP(c_ip)] = PacketTracker(
                    0, 0, 0)
            elif c['matches']['ipv4']['protocol'] == dpkt.ip.IP_PROTO_UDP:
                configs[
                    MudRuleUDP(
                        c_ip,
                        c['matches']['udp'].get('destination-port', dict()).get('port'),
                        c['matches']['udp'].get('source-port', dict()).get('port'),
                    )
                ] = PacketTracker(0, 0, 0)
            elif c['matches']['ipv4']['protocol'] == dpkt.ip.IP_PROTO_TCP:
                configs[
                    MudRuleTCP(
                        c_ip,
                        c['matches']['tcp'].get('destination-port', dict()).get('port'),
                        c['matches']['tcp'].get('source-port', dict()).get('port'),
                    )
                ] = PacketTracker(0, 0, 0)
            else:
                if raise_on_unknown_rule:
                    protocol = c['matches']['ipv4']['protocol']
                    raise Exception(f'Unknown rule: {protocol} in file {mud_file}')

    return configs
