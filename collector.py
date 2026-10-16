"""SimpleFlow: single-exporter UDP NetFlow v5/v9 and IPFIX collector.

Standard library only. Counters are raw (not sampling-adjusted). The HTTP UI
binds to loopback by default; put an authenticated reverse proxy in front of it
before exposing it to a network. See README.md for supported information elements.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sqlite3
import struct
import threading
import time
from collections import Counter
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent
PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6", 89: "OSPF"}
SERVICES = {22: "SSH", 53: "DNS", 80: "HTTP", 123: "NTP", 161: "SNMP", 443: "HTTPS", 445: "SMB", 500: "IPsec", 993: "IMAPS", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-alt", 8443: "HTTPS-alt"}


class DecodeError(ValueError):
    pass


def number(raw: bytes) -> int:
    return int.from_bytes(raw, "big")


class Decoder:
    """Template/session state is scoped by exporter transport port and domain."""
    def __init__(self):
        self.templates = {}
        self.sequences = {}
        self.uptimes = {}
        self.stats = Counter()

    def decode(self, data: bytes, peer: tuple, now: float | None = None) -> list[dict]:
        now = time.time() if now is None else now
        if len(data) < 2:
            raise DecodeError("Truncated datagram")
        version = number(data[:2])
        if version == 5:
            if len(data) < 24:
                raise DecodeError("Truncated v5 header")
            _, count, uptime, seconds, nanos, seq, engine_type, engine_id, sampling = struct.unpack("!HHIIIIBBH", data[:24])
            if count > 30 or len(data) != 24 + count * 48:
                raise DecodeError("Invalid v5 record count/length")
            domain = engine_type * 256 + engine_id
            key = (peer, version, domain)
            self._reboot(key, uptime)
            records = []
            for offset in range(24, len(data), 48):
                r = struct.unpack("!IIIHHIIIIHHBBBBHHBBH", data[offset:offset + 48])
                records.append(self._record({8: r[0].to_bytes(4, "big"), 12: r[1].to_bytes(4, "big"), 15: r[2].to_bytes(4, "big"),
                    10: r[3], 14: r[4], 2: r[5], 1: r[6], 22: r[7], 21: r[8], 7: r[9], 11: r[10], 6: r[12],
                    4: r[13], 5: r[14], 16: r[15], 17: r[16], 9: r[17], 13: r[18]}, version, domain, now,
                    sampling=(sampling & 0x3FFF) or 1, export_time=seconds + nanos / 1e9))
            self._sequence(key, seq, count)
            return records
        if version not in (9, 10):
            raise DecodeError(f"Unsupported export version {version}")
        header = 20 if version == 9 else 16
        if len(data) < header:
            raise DecodeError("Truncated export header")
        if version == 9:
            _, _, uptime, seconds, seq, domain = struct.unpack("!HHIIII", data[:20])
        else:
            _, length, seconds, seq, domain = struct.unpack("!HHIII", data[:16])
            if length != len(data):
                raise DecodeError("IPFIX message length mismatch")
        key = (peer, version, domain)
        if version == 9:
            self._reboot(key, uptime)
        # UDP templates expire; stale templates must never decode a new layout.
        self.templates = {k: v for k, v in self.templates.items() if now - v[2] < 1800}
        template_set = 0 if version == 9 else 2
        options_set = 1 if version == 9 else 3
        records, total_records, uncertain = [], 0, False
        offset = header
        while offset < len(data):
            if len(data) - offset < 4:
                raise DecodeError("Truncated set header")
            set_id, length = struct.unpack_from("!HH", data, offset)
            if length < 4 or offset + length > len(data):
                raise DecodeError("Invalid set length")
            payload = data[offset + 4:offset + length]
            offset += length
            if set_id in (template_set, options_set):
                self._templates(payload, key, version, set_id == options_set, now)
            elif set_id >= 256:
                template = self.templates.get((key, set_id))
                if not template:
                    self.stats["unknown_template_sets"] += 1
                    uncertain = True
                    continue
                fields, options, _ = template
                cursor = 0
                minimum = sum(1 if length == 65535 else length for _, length, _ in fields)
                while len(payload) - cursor >= minimum:
                    values = {}
                    for field, size, enterprise in fields:
                        if size == 65535:
                            if cursor >= len(payload):
                                raise DecodeError("Truncated variable-length field")
                            size = payload[cursor]
                            cursor += 1
                            if size == 255:
                                if cursor + 2 > len(payload):
                                    raise DecodeError("Truncated variable-length prefix")
                                size = number(payload[cursor:cursor + 2])
                                cursor += 2
                        if cursor + size > len(payload):
                            raise DecodeError("Truncated data record")
                        value = payload[cursor:cursor + size]
                        cursor += size
                        if not enterprise:
                            values[field] = value if field in (8, 12, 15, 27, 28, 62) else number(value)
                    total_records += 1
                    if not options:
                        record = self._record(values, version, domain, now, export_time=seconds)
                        if record["src"] != "—" and record["dst"] != "—":
                            records.append(record)
                        else:
                            self.stats["non_flow_records"] += 1
                    else:
                        self.stats["options_records"] += 1
                if len(payload) - cursor > 3 or any(payload[cursor:]):
                    raise DecodeError("Invalid data set padding")
        self._sequence(key, seq, 1 if version == 9 else total_records, uncertain and version == 10)
        return records

    def _templates(self, payload, key, version, options, now):
        cursor = 0
        while cursor + 4 <= len(payload):
            template_id, count = struct.unpack_from("!HH", payload, cursor)
            cursor += 4
            if count == 0:
                # Template withdrawal is not permitted over UDP (RFC 7011 §8.4).
                raise DecodeError("Zero-field UDP template")
            if template_id < 256:
                raise DecodeError("Invalid template ID")
            if options:
                if cursor + 2 > len(payload):
                    raise DecodeError("Truncated options template")
                extra = number(payload[cursor:cursor + 2])
                cursor += 2
                if version == 9:
                    if count % 4 or extra % 4:
                        raise DecodeError("Invalid v9 options field lengths")
                    count = (count + extra) // 4
                elif extra > count:
                    raise DecodeError("Invalid scope count")
            if not 0 < count <= 256:
                raise DecodeError("Template has too many fields")
            fields = []
            for _ in range(count):
                if cursor + 4 > len(payload):
                    raise DecodeError("Truncated template field")
                field, size = struct.unpack_from("!HH", payload, cursor)
                cursor += 4
                enterprise = 0
                if version == 10 and field & 0x8000:
                    field &= 0x7FFF
                    if cursor + 4 > len(payload):
                        raise DecodeError("Truncated enterprise number")
                    enterprise = number(payload[cursor:cursor + 4]) or -1
                    cursor += 4
                if size == 0 or (version == 9 and size == 65535):
                    raise DecodeError("Invalid field length")
                fields.append((field, size, enterprise))
            if len(self.templates) >= 2048 and (key, template_id) not in self.templates:
                raise DecodeError("Template cache capacity exceeded")
            self.templates[(key, template_id)] = (fields, options, now)
        if len(payload) - cursor > 3 or any(payload[cursor:]):
            raise DecodeError("Invalid template padding")

    def _reboot(self, key, uptime):
        previous = self.uptimes.get(key)
        if previous is not None and uptime < previous and previous - uptime < 0x80000000:
            self.templates = {k: v for k, v in self.templates.items() if k[0] != key}
            self.sequences.pop(key, None)
            self.stats["exporter_restarts_or_reordering"] += 1
        self.uptimes[key] = uptime

    def _sequence(self, key, seq, increment, uncertain=False):
        previous = self.sequences.get(key)
        label = "sequence_missing_packets" if key[1] == 9 else "sequence_missing_records"
        if previous is not None:
            delta = (seq - previous) & 0xFFFFFFFF
            if 0 < delta < 0x80000000:
                self.stats[label] += delta
            elif delta >= 0x80000000:
                self.stats["sequence_resets_or_reordering"] += 1
                return
        self.sequences[key] = None if uncertain else (seq + increment) & 0xFFFFFFFF
        if len(self.sequences) > 2048:
            self.sequences = {key: self.sequences[key]}
            self.uptimes = {key: self.uptimes[key]} if key in self.uptimes else {}

    @staticmethod
    def _record(v, version, domain, now, sampling=None, export_time=None):
        def address(*fields):
            for field in fields:
                if field in v:
                    try:
                        return str(ipaddress.ip_address(v[field]))
                    except ValueError:
                        raise DecodeError("Invalid address length")
            return "—"
        src, dst = address(8, 27), address(12, 28)
        duration = None
        if 152 in v and 153 in v:
            duration = max(0, v[153] - v[152]) / 1000
        elif 150 in v and 151 in v:
            duration = max(0, v[151] - v[150])
        elif 21 in v and 22 in v:
            duration = ((v[21] - v[22]) & 0xFFFFFFFF) / 1000
        proto, sport, dport = v.get(4, 0), v.get(7, 0), v.get(11, 0)
        service = SERVICES.get(dport) or SERVICES.get(sport) or PROTOCOLS.get(proto, f"IP {proto}")
        return dict(src=src, dst=dst, srcPort=sport, dstPort=dport, protocol=PROTOCOLS.get(proto, f"IP {proto}"), protocolNumber=proto,
            bytes=v.get(1, v.get(85, 0)), packets=v.get(2, v.get(86, 0)), flags=v.get(6, 0), tos=v.get(5, 0), dscp=v.get(195, v.get(5, 0) >> 2),
            input=v.get(10, 0), output=v.get(14, 0), srcAs=v.get(16, 0), dstAs=v.get(17, 0), srcMask=v.get(9, v.get(29)), dstMask=v.get(13, v.get(30)),
            nextHop=address(15, 62), duration=duration, version=version, domain=domain, received=now, exportTime=export_time,
            sampling=sampling, application=service, direction="Unclassified")


class Collector:
    def __init__(self, exporter, db_path, internal_networks, name="edge-router-01", port=2055, retention=24):
        self.exporter, self.name, self.port = exporter, name, port
        self.networks = [ipaddress.ip_network(n.strip()) for n in internal_networks.split(",")]
        self.retention = retention
        self.decoder, self.lock = Decoder(), threading.RLock()
        self.stats = Counter()
        self.last_seen = None
        self.last_error = None
        self.started = time.time()
        self.versions = set()
        self.last_cleanup = 0
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS flows (id INTEGER PRIMARY KEY, received REAL, bytes INTEGER, packets INTEGER, protocol TEXT, src TEXT, dst TEXT, data TEXT)")
        self.db.execute("CREATE INDEX IF NOT EXISTS flows_received ON flows(received)")
        self.db.commit()

    def ingest(self, data, peer):
        with self.lock:
            if peer[0] != self.exporter:
                self.stats["rejected_exporter_datagrams"] += 1
                return
            self.stats["datagrams"] += 1
            self.stats["datagram_bytes"] += len(data)
            try:
                records = self.decoder.decode(data, peer)
                for r in records:
                    src = any(ipaddress.ip_address(r["src"]) in n for n in self.networks)
                    dst = any(ipaddress.ip_address(r["dst"]) in n for n in self.networks)
                    r["direction"] = "Internal" if src and dst else "Egress" if src else "Ingress" if dst else "Transit"
                    # SQLite uses signed 64-bit integers; reject unrepresentable counters.
                    if r["bytes"] > 0x7FFFFFFFFFFFFFFF or r["packets"] > 0x7FFFFFFFFFFFFFFF:
                        raise DecodeError("Counter exceeds storage range")
                self.db.executemany("INSERT INTO flows (received,bytes,packets,protocol,src,dst,data) VALUES (?,?,?,?,?,?,?)",
                    [(r["received"], r["bytes"], r["packets"], r["protocol"], r["src"], r["dst"], json.dumps(r)) for r in records])
                now = time.time()
                if now - self.last_cleanup > 60:
                    self.db.execute("DELETE FROM flows WHERE received < ?", (now - self.retention * 3600,))
                    self.db.execute("DELETE FROM flows WHERE id <= (SELECT id FROM flows ORDER BY id DESC LIMIT 1 OFFSET 249999)")
                    self.last_cleanup = now
                self.db.commit()
                self.stats["records"] += len(records)
                self.versions.add(number(data[:2]))
                self.last_seen = now
            except (ValueError, struct.error, sqlite3.Error) as exc:
                self.db.rollback()
                self.stats["malformed_datagrams"] += 1
                self.last_error = str(exc)

    def snapshot(self, minutes=60):
        now = time.time()
        with self.lock:
            rows = self.db.execute("SELECT id,data FROM flows WHERE received>=? ORDER BY received DESC LIMIT 250000", (now-minutes*60,)).fetchall()
            records = [dict(json.loads(data), id=ident) for ident, data in rows]
            stats = dict(self.stats + self.decoder.stats)
            templates = [dict(id=k[1], version=k[0][1], domain=k[0][2], fields=len(v[0]), options=v[1], age=round(now-v[2])) for k,v in self.decoder.templates.items() if now-v[2]<1800]
            exporter = dict(name=self.name, ip=self.exporter, port=self.port, lastSeen=self.last_seen, versions=sorted(self.versions),
                status="healthy" if self.last_seen and now-self.last_seen<60 else "idle", uptime=now-self.started, stats=stats, templates=templates, lastError=self.last_error,
                retentionHours=self.retention, networks=[str(n) for n in self.networks])
        return summarize(records, minutes, now, exporter)


def summarize(records, minutes, now, exporter):
    bins = 48
    width = minutes * 60 / bins
    series = [dict(time=(now-minutes*60+i*width)*1000, ingress=0, egress=0, internal=0, flows=0) for i in range(bins)]
    protocols, apps, sources, interfaces = {}, {}, {}, {}
    total_bytes = total_packets = 0
    for r in records:
        total_bytes += r["bytes"]
        total_packets += r["packets"]
        bucket = min(bins-1, max(0, int((r["received"]-(now-minutes*60))/width)))
        direction = r["direction"].lower()
        series[bucket][direction if direction in ("ingress", "egress") else "internal"] += r["bytes"]*8/width
        series[bucket]["flows"] += 1
        for mapping, key in ((protocols, r["protocol"]), (apps, r["application"]), (sources, r["src"])):
            item = mapping.setdefault(key, dict(name=key, bytes=0, packets=0, flows=0))
            item["bytes"] += r["bytes"]
            item["packets"] += r["packets"]
            item["flows"] += 1
        for key, direction in ((r["input"], "ingress"), (r["output"], "egress")):
            item = interfaces.setdefault(key, dict(id=key, name=f"ifIndex {key}", ingress=0, egress=0, flows=0))
            item[direction] += r["bytes"]*8/(minutes*60)
            item["flows"] += 1
    sort = lambda mapping: sorted(mapping.values(), key=lambda r:r["bytes"], reverse=True)
    return dict(mode="live", now=now*1000, minutes=minutes, exporter=exporter, series=series,
        totals=dict(bytes=total_bytes, packets=total_packets, flows=len(records), sources=len(sources), bps=total_bytes*8/(minutes*60), pps=total_packets/(minutes*60)),
        protocols=sort(protocols), applications=sort(apps), talkers=sort(sources)[:25], interfaces=list(interfaces.values()),
        flows=records[:2000], flowLimit=2000, flowTruncated=len(records)>2000,
        measurement="Raw counters, grouped by collector receipt time. Application labels are inferred from ports.")


def run():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--exporter", default="127.0.0.1", help="Only accept this exporter IPv4 address")
    p.add_argument("--name", default="edge-router-01")
    p.add_argument("--udp-host", default="0.0.0.0")
    p.add_argument("--udp-port", type=int, default=2055)
    p.add_argument("--http-host", default="127.0.0.1")
    p.add_argument("--http-port", type=int, default=8080)
    p.add_argument("--networks", default="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16", help="Comma-separated internal CIDRs for traffic direction")
    p.add_argument("--db", default=str(ROOT / ".data" / "flows.sqlite3"))
    p.add_argument("--retention-hours", type=int, default=24)
    p.add_argument("--demo", action="store_true", help="Serve the demonstration dashboard")
    args = p.parse_args()
    ipaddress.IPv4Address(args.exporter)
    if not 1 <= args.retention_hours <= 720:
        p.error("retention-hours must be 1–720")
    Path(args.db).parent.mkdir(parents=True, exist_ok=True)
    collector = Collector(args.exporter, args.db, args.networks, args.name, args.udp_port, args.retention_hours)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4*1024*1024)
    udp.bind((args.udp_host, args.udp_port))

    def receive():
        while True:
            try:
                data, peer = udp.recvfrom(65535)
                collector.ingest(data, peer)
            except OSError:
                break

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(ROOT / "dist"), **kw)

        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path == "/api/snapshot":
                try:
                    minutes = int(parse_qs(parsed.query).get("minutes", ["60"])[0])
                    if minutes not in (15, 60, 360, 1440):
                        raise ValueError()
                except ValueError:
                    self.send_error(400, "Invalid time range")
                    return
                body = json.dumps({"mode": "demo"} if args.demo else collector.snapshot(minutes)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                if parsed.path in ("/", "/index.html"):
                    self.path = "/index.html"
                super().do_GET()

        def list_directory(self, path):
            self.send_error(404)

    server = ThreadingHTTPServer((args.http_host, args.http_port), Handler)
    threading.Thread(target=receive, daemon=True).start()
    print(f"SimpleFlow → http://{args.http_host}:{args.http_port}", flush=True)
    print(f"UDP {args.udp_host}:{args.udp_port} · allowed exporter {args.exporter} · {'demo' if args.demo else 'live'} mode", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        udp.close()
        server.server_close()
        collector.db.close()


if __name__ == "__main__":
    run()
