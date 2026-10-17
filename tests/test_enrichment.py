import socket
import tempfile
import unittest
from pathlib import Path
from enrichment import Enricher


class EnrichmentTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.path = str(Path(self.folder.name) / 'cache.db')
        self.calls = []

        def api(endpoint, resource):
            self.calls.append((endpoint, resource))
            return {'asns': [15169, 15169], 'prefix': '8.8.8.0/24'} if endpoint == 'network-info' else {'holder': 'GOOGLE'}

        self.e = Enricher(self.path, ptr_lookup=lambda ip: ('dns.google.', [], [ip]), api_lookup=api, start_workers=False)

    def tearDown(self):
        self.e.close()
        self.folder.cleanup()

    def test_public_routing_and_holder_cached(self):
        self.e._lookup('bgp', '8.8.8.8')
        self.e._lookup('bgp', '8.8.8.9')
        self.e._lookup('dns', '8.8.8.8')
        result = self.e.snapshot(['8.8.8.8'])['8.8.8.8']
        self.assertEqual(result['asns'], [{'asn': 15169, 'holder': 'GOOGLE'}])
        self.assertEqual(result['prefix'], '8.8.8.0/24')
        self.assertEqual(result['hostname'], 'dns.google')
        self.assertEqual(self.calls.count(('as-overview', 'AS15169')), 1)
        self.assertEqual(self.e.status()['pending'], 0)

    def test_private_and_special_never_sent_to_provider(self):
        addresses = ['192.168.1.2', '10.0.0.1', '127.0.0.1', '100.64.0.1', '224.0.0.1', '192.0.2.1', 'fc00::1', 'fe80::1', 'ff02::1', '::']
        result = self.e.snapshot(addresses)
        for address in addresses:
            self.e._lookup('bgp', address)
            self.assertEqual(result[address]['bgpStatus'], 'not_applicable')
        self.assertEqual(self.calls, [])
        self.e._lookup('dns', '192.168.1.2')
        self.assertEqual(self.e.snapshot(['192.168.1.2'])['192.168.1.2']['dnsStatus'], 'resolved')

    def test_queue_deduplicated_bounded_and_snapshot_nonblocking(self):
        addresses = [f'11.0.{i // 256}.{i % 256}' for i in range(1000)]
        self.e.snapshot(addresses)
        self.e.snapshot(addresses)
        self.assertEqual(self.e.status()['pending'], 512)
        self.assertEqual(self.calls, [])

    def test_negative_dns_and_error_backoff_preserve_metadata(self):
        def missing(ip):
            raise socket.herror(1, 'Unknown host')
        self.e.ptr_lookup = missing
        self.e._lookup('dns', '8.8.8.8')
        self.assertEqual(self.e.snapshot(['8.8.8.8'])['8.8.8.8']['dnsStatus'], 'not_found')
        self.e._lookup('bgp', '8.8.8.8')
        def failure(*args):
            raise TimeoutError('Lookup timed out')
        self.e.api_lookup = failure
        self.e._lookup('bgp', '8.8.8.8')
        result = self.e.snapshot(['8.8.8.8'])['8.8.8.8']
        self.assertEqual(result['bgpStatus'], 'error')
        self.assertEqual(result['asns'][0]['asn'], 15169)
        self.assertEqual(self.e.status()['errors'], 1)

    def test_persistence_expiry_and_disabled(self):
        self.e._lookup('dns', '8.8.8.8')
        other = Enricher(self.path, asn=False, start_workers=False)
        try:
            result = other.snapshot(['8.8.8.8'])['8.8.8.8']
            self.assertEqual(result['hostname'], 'dns.google')
            self.assertEqual(result['bgpStatus'], 'disabled')
            other.db.execute('UPDATE cache SET expires=0')
            other.db.commit()
            self.assertTrue(other.snapshot(['8.8.8.8'])['8.8.8.8']['dnsStale'])
            self.assertEqual(other.status()['pending'], 1)
        finally:
            other.close()

    def test_ipv6_multiple_origins_and_mismatched_prefix(self):
        self.e.api_lookup = lambda endpoint, resource: {'asns': ['AS13335', 'AS64500'], 'prefix': '2606:4700::/32'} if endpoint == 'network-info' else {'holder': resource}
        self.e._lookup('bgp', '2606:4700:4700::1111')
        result = self.e.snapshot(['2606:4700:4700::1111'])['2606:4700:4700::1111']
        self.assertEqual([a['asn'] for a in result['asns']], [13335, 64500])
        self.e._lookup('bgp', '8.8.8.8')
        self.assertEqual(self.e.snapshot(['8.8.8.8'])['8.8.8.8']['bgpStatus'], 'error')


if __name__ == '__main__':
    unittest.main()
