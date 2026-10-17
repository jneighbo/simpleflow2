import ipaddress
import struct
import tempfile
import unittest
from pathlib import Path
from test_collector import flow_set, message
from collector import Collector, Decoder


def biflow(ipv6=False, sequence=0, reverse_bytes=9000, reverse_packets=8, reverse_flags=True):
    endpoints = ('2001:db8::7', '2001:db8:1::42') if ipv6 else ('10.0.0.7', '203.0.113.42')
    values = [(27 if ipv6 else 8, ipaddress.ip_address(endpoints[0]).packed, 0),
              (28 if ipv6 else 12, ipaddress.ip_address(endpoints[1]).packed, 0)]
    for ie, value, size, pen in [(7, 52300, 2, 0), (11, 443, 2, 0), (4, 6, 1, 0),
            (1, 2000, 8, 0), (2, 4, 8, 0), (6, 2, 1, 0), (5, 184, 1, 0),
            (10, 2, 4, 0), (14, 2, 4, 0), (16, 64512, 4, 0),
            (154, 4000000000 << 32, 8, 0), (155, (4000000002 << 32) + (1 << 31), 8, 0),
            (1, reverse_bytes, 8, 29305), (2, reverse_packets, 8, 29305), (5, 0, 1, 29305),
            (1, 999999, 8, 32473)]:
        values.append((ie, value.to_bytes(size, 'big'), pen))
    if reverse_flags:
        values.append((6, b'\x12', 29305))
    template = struct.pack('!HH', 256, len(values))
    for ie, value, pen in values:
        template += struct.pack('!HH', ie | (0x8000 if pen else 0), len(value))
        if pen:
            template += struct.pack('!I', pen)
    return message(10, [flow_set(2, template), flow_set(256, b''.join(v for _, v, _ in values))], seq=sequence)


class BiflowTests(unittest.TestCase):
    def test_both_directions_ipv4_ipv6_and_no_false_sequence_gap(self):
        for ipv6 in (False, True):
            decoder = Decoder()
            forward, reverse = decoder.decode(biflow(ipv6), ('127.0.0.1', 9999))
            self.assertEqual((reverse['src'], reverse['dst'], reverse['srcPort'], reverse['dstPort']),
                             (forward['dst'], forward['src'], 443, 52300))
            self.assertEqual((forward['bytes'], reverse['bytes'], reverse['packets']), (2000, 9000, 8))
            self.assertEqual((forward['flags'], reverse['flags'], reverse['dscp']), (2, 18, 0))
            self.assertEqual(reverse['srcAs'], 0)
            self.assertEqual((reverse['input'], reverse['output']), (2, 2))
            self.assertEqual((reverse['duration'], reverse['durationScope']), (2.5, 'shared conversation'))
            self.assertEqual(forward['flowRecordId'], reverse['flowRecordId'])
            decoder.decode(biflow(ipv6, sequence=1), ('127.0.0.1', 9999))
            self.assertEqual(decoder.stats['sequence_missing_records'], 0)
            self.assertEqual(decoder.stats['sequence_resets_or_reordering'], 0)

    def test_empty_reverse_does_not_copy_forward_flags_or_counters(self):
        _, reverse = Decoder().decode(biflow(reverse_bytes=0, reverse_packets=0, reverse_flags=False), ('127.0.0.1', 9999))
        self.assertEqual((reverse['bytes'], reverse['packets'], reverse['flags']), (0, 0, 0))

    def test_totals_direction_pairing_and_persistence(self):
        with tempfile.TemporaryDirectory() as folder:
            path = str(Path(folder) / 'flows.db')
            collector = Collector('127.0.0.1', path, '10.0.0.0/8')
            collector.ingest(biflow(), ('127.0.0.1', 9999))
            result = collector.snapshot()
            self.assertEqual((result['totals']['bytes'], result['totals']['packets'], result['totals']['flows'], result['totals']['exportRecords']), (11000, 12, 2, 1))
            self.assertEqual({r['direction'] for r in result['flows']}, {'Ingress', 'Egress'})
            self.assertEqual(collector.stats['wire_flow_records'], 1)
            self.assertEqual(collector.stats['biflow_records'], 1)
            self.assertEqual(result['exporter']['templates'][0]['reverseFields'], 4)
            collector.db.close()
            collector = Collector('127.0.0.1', path, '10.0.0.0/8')
            self.assertEqual(collector.snapshot()['totals']['exportRecords'], 1)
            collector.db.close()
