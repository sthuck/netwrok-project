from abc import ABC
import dpkt
from .ip_matcher import AbstractIpMatcher


class AbstractMudRule(ABC):
    after_first_packet = False

    def verify(self, ip_packet: dpkt.ip.IP) -> bool:
        pass

    def is_new_connection(self, ip_packet: dpkt.ip.IP) -> bool:
        """
        Default behavior: on first packet for this specific rule, return true, all following packets, returns false
        :param ip_packet:
        :return:
        """
        isFirstPacket = not self.after_first_packet
        self.after_first_packet = True
        return isFirstPacket

    def __eq__(self, other) -> bool:
        pass

    def __hash__(self):
        return self.__repr__().__hash__()


class MudRuleIP(AbstractMudRule):
    def __init__(self, protocol, src_ip_network: AbstractIpMatcher = None, dst_ip_network: AbstractIpMatcher = None):
        self.protocol = protocol
        self.src_ip_network: AbstractIpMatcher = src_ip_network
        self.dst_ip_network: AbstractIpMatcher = dst_ip_network

    def __repr__(self):
        return f'filtered for dest_ip: {self.dst_ip_network}, src_ip:{self.src_ip_network} protocol: {self.protocol}'

    __hash__ = AbstractMudRule.__hash__

    def verify(self, ip_packet: dpkt.ip.IP) -> bool:
        if self.protocol != ip_packet.p:
            return False
        if self.src_ip_network is not None:
            if not self.src_ip_network.is_match(ip_packet.src):
                return False
        if self.dst_ip_network is not None:
            if not self.dst_ip_network.is_match(ip_packet.dst):
                return False
        return True

    def is_new_connection(self, ip_packet: dpkt.ip.IP) -> bool:
        raise Exception('cant call this function on rawIp packet, call on specific protocol')

    def __eq__(self, other) -> bool:
        if type(other) == MudRuleIP:
            other_ip: MudRuleIP = other
            return other_ip.protocol == self.protocol and self.dst_ip_network == other_ip.dst_ip_network \
                   and self.src_ip_network == other_ip.src_ip_network
        return False


class MudRuleUDP(AbstractMudRule):
    def __init__(self, config_ip: MudRuleIP, dest_port=None, src_port=None):
        self.dest_port = dest_port
        self.src_port = src_port
        self.config_ip = config_ip

    def __repr__(self):
        return f'UDP: filtered for dest_port: {self.dest_port}, src_port:{self.src_port} ' + repr(self.config_ip)

    __hash__ = AbstractMudRule.__hash__

    def __eq__(self, other) -> bool:
        if type(other) == MudRuleUDP:
            other_udp: MudRuleUDP = other
            return self.config_ip == other_udp.config_ip and self.src_port == other_udp.src_port and self.dest_port == other_udp.dest_port
        return False

    def verify(self, ip_packet: dpkt.ip.IP) -> bool:
        if not self.config_ip.verify(ip_packet):
            return False
        if not ip_packet.p == dpkt.ip.IP_PROTO_UDP:
            return False
        if self.dest_port is not None:
            if self.dest_port != ip_packet.data.dport:
                return False
        if self.src_port is not None:
            if self.src_port != ip_packet.data.sport:
                return False
        return True


class MudRuleTCP(AbstractMudRule):
    def __init__(self, config_ip: MudRuleIP, dest_port=None, src_port=None):
        self.dest_port = dest_port
        self.src_port = src_port
        self.config_ip = config_ip

    def __repr__(self):
        return f'TCP: filtered for dest_port: {self.dest_port}, src_port:{self.src_port} ' + repr(self.config_ip)

    __hash__ = AbstractMudRule.__hash__

    def __eq__(self, other) -> bool:
        if type(other) == MudRuleTCP:
            other_tcp: MudRuleTCP = other
            return self.config_ip == other_tcp.config_ip and self.src_port == other_tcp.src_port and \
                   self.dest_port == other_tcp.dest_port
        return False

    def verify(self, ip_packet: dpkt.ip.IP) -> bool:
        if not self.config_ip.verify(ip_packet):
            return False
        if not ip_packet.p == dpkt.ip.IP_PROTO_TCP:
            return False
        if self.dest_port is not None:
            if self.dest_port != ip_packet.data.dport:
                return False
        if self.src_port is not None:
            if self.src_port != ip_packet.data.sport:
                return False
        return True

    def is_new_connection(self, ip_packet: dpkt.ip.IP) -> bool:
        """
        using only SYN for new connection, which might not be 100% accurate. [SYN + ACK]
        or the full handshake [SYN, SYN-ACK, ACK] would be better but harder to implement
        :param ip_packet:
        :return:
        """
        return ip_packet.data.flags == dpkt.tcp.TH_SYN


class MudRuleICMP(AbstractMudRule):
    def __init__(self, icmp_type, icmp_code, config_ip: MudRuleIP):
        self.type = icmp_type
        self.code = icmp_code
        self.config_ip = config_ip

    def __repr__(self):
        return f'ICMP: filtered for icmp_type: {self.type}, icmp_code:{self.code} ' + repr(self.config_ip)

    __hash__ = AbstractMudRule.__hash__

    def __eq__(self, other) -> bool:
        if type(other) == MudRuleICMP:
            other_icmp: MudRuleICMP = other
            return self.config_ip == other_icmp.config_ip and self.code == other_icmp.code and self.type == other_icmp.type
        return False

    def verify(self, ip_packet: dpkt.ip.IP):
        if not self.config_ip.verify(ip_packet):
            return False
        if not ip_packet.p == dpkt.ip.IP_PROTO_ICMP:
            return False
        if self.type != ip_packet.data.type:
            return False
        if self.code != ip_packet.data.code:
            return False
        return True


class MudRuleIGMP(AbstractMudRule):
    def __init__(self, config_ip: MudRuleIP):
        self.config_ip = config_ip

    def __eq__(self, other) -> bool:
        if type(other) == MudRuleIGMP:
            other_igmp: MudRuleIGMP = other
            return self.config_ip == other_igmp.config_ip
        return False

    def __repr__(self):
        return f'IGMP: ' + repr(self.config_ip)

    __hash__ = AbstractMudRule.__hash__

    def verify(self, ip_packet: dpkt.ip.IP):
        if not self.config_ip.verify(ip_packet):
            return False
        if not ip_packet.p == dpkt.ip.IP_PROTO_IGMP:
            return False
        return True
