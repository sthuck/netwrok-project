from unittest import TestCase
from .ip_matcher import DnsIpMatcher, LiteralIpMatcher
import socket


class TestDnsIpMatcher(TestCase):
    def test_is_match(self):
        dns_records = {'192.168.0.1': 'foo.bar.com', '192.168.0.2': 'foo2.bar.com'}
        matcher = DnsIpMatcher('foo.bar.com', dns_records)
        result = matcher.is_match(socket.inet_aton('192.168.0.1'))
        self.assertTrue(result, 'should match when ip address resolves to same hostname')

        result = matcher.is_match(socket.inet_aton('192.168.0.2'))
        self.assertFalse(result, 'should not match when ip address doesnt resolves to same hostname')

        result = matcher.is_match(socket.inet_aton('192.168.0.3'))
        self.assertFalse(result, 'should not match on on unknown ip addresses')

    def test_is_match_wildcard(self):
        dns_records = {'192.168.0.1': 'foo.bar.com', '192.168.0.2': 'foo2.bar.com'}
        matcher = DnsIpMatcher('*.bar.com', dns_records)

        result = matcher.is_match(socket.inet_aton('192.168.0.1'))
        self.assertTrue(result, 'should match when ip address resolves to hostname with wildcard')

    def test_literal_ip_matcher(self):
        matcher = LiteralIpMatcher('192.168.0.1')
        result = matcher.is_match(socket.inet_aton('192.168.0.1'))
        self.assertTrue(result, 'should match on same ip')

        matcher = LiteralIpMatcher('192.168.0.1/32')
        result = matcher.is_match(socket.inet_aton('192.168.0.1'))
        self.assertTrue(result, 'should match on same ip')

        matcher = LiteralIpMatcher('192.168.0.0/16')
        result = matcher.is_match(socket.inet_aton('192.168.5.1'))
        self.assertTrue(result, 'should match on same subnet')

        matcher = LiteralIpMatcher('192.168.0.0/16')
        result = matcher.is_match(socket.inet_aton('192.162.5.1'))
        self.assertFalse(result, 'should match on same subnet')