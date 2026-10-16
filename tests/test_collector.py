import ipaddress
import socket
import struct
import tempfile
import time
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from collector import Collector, Decoder, DecodeError, summarize


def v5(sequence=0, count=1, uptime=30000, sampling=0):
    header = struct.pack('!HHIIIIBBH', 5, count, uptime, 1700000000, 0, sequence, 0, 1, sampling)
    record = struct.pack('!IIIHHIIIIHHBBBBHHBBH', int(ipaddress.IPv4Address('10.0.0.7')),
        int(ipaddress.IPv4Address('203.0.113.42')), int(ipaddress.IPv4Address('10.0.0.1')),
        2, 3, 25, 20000, 10000, 12000, 52300, 443, 0, 0x12, 6, 184, 64512, 64500, 24, 24, 0)
    return header + record * count


FIELDS = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (2, 4), (6, 1)]
PAYLOAD = socket.inet_aton('10.0.0.7') + socket.inet_aton('203.0.113.42') + struct.pack('!HHBIIB', 52300, 443, 6, 20000, 25, 18)


def flow_set(id, data):
    return struct.pack('!HH', id, 4 + len(data)) + data


def template(id=256, fields=FIELDS):
    return struct.pack('!HH', id, len(fields)) + b''.join(struct.pack('!HH', *f) for f in fields)


def message(version=9, sets=None, seq=0, domain=1, uptime=30000):
    payload = b''.join(sets if sets is not None else [flow_set(0 if version == 9 else 2, template()), flow_set(256, PAYLOAD)])
    if version == 9:
        return struct.pack('!HHIIII', 9, 2, uptime, 1700000000, seq, domain) + payload
    return struct.pack('!HHIII', 10, 16 + len(payload), 1700000000, seq, domain) + payload


class DecoderTests(unittest.TestCase):
    def setUp(self):
        self.decoder = Decoder()
        self.peer = ('127.0.0.1', 9999)

    def test_v5_fields_and_sampling(self):
        r = self.decoder.decode(v5(sampling=0x400A), self.peer)[0]
        self.assertEqual((r['src'], r['dst']), ('10.0.0.7', '203.0.113.42'))
        self.assertEqual((r['bytes'], r['packets'], r['flags'], r['dscp']), (20000, 25, 18, 46))
        self.assertEqual((r['input'], r['output'], r['srcAs'], r['dstAs']), (2, 3, 64512, 64500))
        self.assertEqual((r['duration'], r['sampling'], r['application']), (2.0, 10, 'HTTPS'))

    def test_truncated_and_unsupported(self):
        for packet in (b'', b'\x00', v5()[:-1], b'\x00\x07' + bytes(30)):
            with self.assertRaises(DecodeError):
                self.decoder.decode(packet, self.peer)

    def test_v9_cached_template(self):
        self.assertEqual(self.decoder.decode(message(), self.peer)[0]['bytes'], 20000)
        records = self.decoder.decode(message(sets=[flow_set(256, PAYLOAD)], seq=1), self.peer)
        self.assertEqual(records[0]['srcPort'], 52300)

    def test_ipfix_template_and_data(self):
        records = self.decoder.decode(message(version=10), self.peer)
        self.assertEqual((records[0]['version'], records[0]['dstPort']), (10, 443))

    def test_unknown_and_scoped_templates(self):
        self.decoder.decode(message(), self.peer)
        for peer, domain in [(self.peer, 2), (('127.0.0.1', 9998), 1)]:
            self.assertEqual(self.decoder.decode(message(sets=[flow_set(256, PAYLOAD)], domain=domain), peer), [])
        self.assertEqual(self.decoder.stats['unknown_template_sets'], 2)

    def test_template_expiry(self):
        self.decoder.decode(message(), self.peer, now=1000)
        records = self.decoder.decode(message(sets=[flow_set(256, PAYLOAD)], seq=1), self.peer, now=2801)
        self.assertEqual(records, [])

    def test_v5_sequence_gap_and_wrap(self):
        self.decoder.decode(v5(sequence=0xFFFFFFFF), self.peer)
        self.decoder.decode(v5(sequence=0), self.peer)
        self.decoder.decode(v5(sequence=3), self.peer)
        self.assertEqual(self.decoder.stats['sequence_missing_records'], 2)

    def test_v9_sequence_counts_packets(self):
        self.decoder.decode(message(seq=1), self.peer)
        self.decoder.decode(message(seq=4), self.peer)
        self.assertEqual(self.decoder.stats['sequence_missing_packets'], 2)

    def test_ipfix_sequence_counts_records(self):
        self.decoder.decode(message(version=10, sets=[flow_set(2, template()), flow_set(256, PAYLOAD * 2)]), self.peer)
        self.decoder.decode(message(version=10, sets=[flow_set(256, PAYLOAD)], seq=2), self.peer)
        self.assertEqual(self.decoder.stats['sequence_missing_records'], 0)

    def test_reboot_invalidates_templates(self):
        self.decoder.decode(message(uptime=30000), self.peer)
        self.assertEqual(self.decoder.decode(message(sets=[flow_set(256, PAYLOAD)], uptime=500), self.peer), [])

    def test_invalid_set_lengths(self):
        for payload in (struct.pack('!HH', 256, 0), struct.pack('!HH', 256, 9000)):
            with self.assertRaises(DecodeError):
                self.decoder.decode(message(sets=[payload]), self.peer)

    def test_ipfix_ipv6_enterprise_and_variable_length(self):
        fields = [(27, 16), (28, 16), (1, 8), (0x8001, 65535)]
        tpl = template(fields=fields) + struct.pack('!I', 32473)
        data = ipaddress.IPv6Address('2001:db8::1').packed + ipaddress.IPv6Address('2001:db8::2').packed + struct.pack('!Q', 4242) + b'\x03abc'
        r = self.decoder.decode(message(10, [flow_set(2, tpl), flow_set(256, data)]), self.peer)[0]
        self.assertEqual((r['src'], r['bytes']), ('2001:db8::1', 4242))

    def test_ipfix_length_mismatch(self):
        with self.assertRaises(DecodeError):
            self.decoder.decode(message(10) + b'x', self.peer)

    def test_options_records_counted_not_emitted(self):
        tpl = struct.pack('!HHH', 257, 2, 1) + struct.pack('!HHHH', 149, 4, 34, 4)
        records = self.decoder.decode(message(10, [flow_set(3, tpl), flow_set(257, struct.pack('!II', 1, 100))]), self.peer)
        self.assertEqual(records, [])
        self.assertEqual(self.decoder.stats['options_records'], 1)


class CollectorTests(unittest.TestCase):
    def test_single_exporter_storage_and_aggregation(self):
        with tempfile.TemporaryDirectory() as folder:
            c = Collector('127.0.0.1', str(Path(folder) / 'test.db'), '10.0.0.0/8')
            try:
                c.ingest(v5(), ('127.0.0.2', 9000))
                self.assertEqual(c.stats['rejected_exporter_datagrams'], 1)
                self.assertEqual(c.snapshot()['totals']['flows'], 0)
                c.ingest(v5(), ('127.0.0.1', 9000))
                data = c.snapshot(minutes=60)
                self.assertEqual(data['totals']['bytes'], 20000)
                self.assertEqual(data['totals']['packets'], 25)
                self.assertEqual(data['flows'][0]['direction'], 'Egress')
                self.assertEqual(data['totals']['bps'], 20000 * 8 / 3600)
                self.assertAlmostEqual(sum(b['egress'] for b in data['series']) * 75 / 8, 20000)
                c.ingest(v5()[:-1], ('127.0.0.1', 9000))
                self.assertEqual(c.snapshot()['totals']['flows'], 1)
                self.assertEqual(c.stats['malformed_datagrams'], 1)
            finally:
                c.db.close()

    def test_persistence_and_window_filter(self):
        with tempfile.TemporaryDirectory() as folder:
            path = str(Path(folder) / 'test.db')
            c = Collector('127.0.0.1', path, '10.0.0.0/8')
            c.ingest(v5(), ('127.0.0.1', 9000))
            c.db.close()
            c = Collector('127.0.0.1', path, '10.0.0.0/8')
            self.assertEqual(c.snapshot()['totals']['flows'], 1)
            c.db.execute('UPDATE flows SET received=?', (time.time() - 7200,))
            c.db.commit()
            self.assertEqual(c.snapshot(minutes=60)['totals']['flows'], 0)
            self.assertEqual(c.snapshot(minutes=360)['totals']['flows'], 1)
            c.db.close()


if __name__ == '__main__':
    unittest.main()
