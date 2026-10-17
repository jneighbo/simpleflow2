"""Bounded, cached endpoint enrichment outside the UDP ingestion path.

PTR queries use the machine's system resolver, including internal DNS. Only
globally routable unicast addresses are sent to RIPEstat for BGP origin data.
This is current routing metadata, not the route at the time of an old flow.
"""
from __future__ import annotations

import ipaddress
import json
import queue
import socket
import sqlite3
import threading
import time
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def public_unicast(value):
    address = ipaddress.ip_address(value)
    return address.is_global and not (address.is_multicast or address.is_reserved)


class Enricher:
    def __init__(self, db_path, rdns=True, asn=True, ptr_lookup=None, api_lookup=None, start_workers=True):
        self.rdns, self.asn = rdns, asn
        self.ptr_lookup = ptr_lookup or socket.gethostbyaddr
        self.api_lookup = api_lookup or self._request
        self.lock = threading.RLock()
        self.rate_lock = threading.Lock()
        self.asn_lock = threading.Lock()
        self.stop = threading.Event()
        self.next_request = 0
        self.pending = set()
        self.jobs = {kind: queue.Queue(maxsize=256) for kind in ("dns", "bgp")}
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS cache (kind TEXT, key TEXT, value TEXT, expires REAL, updated REAL, PRIMARY KEY(kind,key))")
        self.db.commit()
        self.workers = []
        self.last_error = None
        self.completed = 0
        self.errors = 0
        self.closed = False
        if start_workers:
            # A slow OS resolver cannot occupy the independent HTTP workers.
            for kind, enabled in (("dns", rdns), ("bgp", asn)):
                if enabled:
                    for index in range(2):
                        thread = threading.Thread(target=self._worker, args=(kind,), name=f"enrichment-{kind}-{index}", daemon=True)
                        thread.start()
                        self.workers.append(thread)

    def _cached(self, kind, key):
        with self.lock:
            row = self.db.execute("SELECT value,expires,updated FROM cache WHERE kind=? AND key=?", (kind, key)).fetchone()
        if row:
            return json.loads(row[0]), row[1], row[2]
        return None

    def _save(self, kind, key, value, ttl):
        now = time.time()
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO cache VALUES (?,?,?,?,?)", (kind, key, json.dumps(value), now+ttl, now))
            if self.completed % 100 == 0:
                self.db.execute("DELETE FROM cache WHERE expires < ?", (now - 86400,))
                self.db.execute("DELETE FROM cache WHERE rowid IN (SELECT rowid FROM cache ORDER BY updated DESC LIMIT -1 OFFSET 20000)")
            self.db.commit()

    def _schedule(self, kind, address):
        with self.lock:
            key = (kind, address)
            if key in self.pending or self.stop.is_set():
                return
            try:
                self.jobs[kind].put_nowait(address)
                self.pending.add(key)
            except queue.Full:
                pass  # Try again on the next dashboard refresh.

    def snapshot(self, addresses):
        result = {}
        for address in dict.fromkeys(addresses):
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                continue
            entry = {"hostname": None, "asns": [], "prefix": None}
            for kind, enabled in (("dns", self.rdns), ("bgp", self.asn)):
                status_key = "dnsStatus" if kind == "dns" else "bgpStatus"
                if not enabled:
                    entry[status_key] = "disabled"
                    continue
                if (kind == "bgp" and not public_unicast(address)) or ip.is_multicast or ip.is_unspecified:
                    entry[status_key] = "not_applicable"
                    continue
                cached = self._cached(kind, address)
                if cached:
                    value, expires, updated = cached
                    entry.update({k: v for k, v in value.items() if k not in ("status", "error")})
                    entry[status_key] = value["status"]
                    entry[kind+"Updated"] = updated
                    entry[kind+"Stale"] = expires <= time.time()
                    if value.get("error"):
                        entry[kind+"Error"] = value["error"]
                else:
                    entry[status_key] = "pending"
                if not cached or cached[1] <= time.time():
                    self._schedule(kind, address)
            result[address] = entry
        return result

    def _worker(self, kind):
        while not self.stop.is_set():
            try:
                address = self.jobs[kind].get(timeout=.5)
            except queue.Empty:
                continue
            try:
                self._lookup(kind, address)
            finally:
                with self.lock:
                    self.pending.discard((kind, address))
                self.jobs[kind].task_done()

    def _lookup(self, kind, address):
        try:
            if kind == "dns":
                try:
                    hostname = self.ptr_lookup(address)[0].rstrip(".")[:253]
                    value, ttl = {"status": "resolved", "hostname": hostname}, 900
                except socket.herror:
                    value, ttl = {"status": "not_found", "hostname": None}, 300
            else:
                if not public_unicast(address):
                    return  # Defense in depth: never send private/special IPs.
                data = self.api_lookup("network-info", address)
                prefix = data.get("prefix")
                if prefix:
                    network = ipaddress.ip_network(prefix, strict=False)
                    if ipaddress.ip_address(address) not in network:
                        raise ValueError("Routing response does not contain the queried address")
                    prefix = str(network)
                asns = []
                for raw in list(dict.fromkeys(data.get("asns") or []))[:16]:
                    asn = int(str(raw).removeprefix("AS"))
                    if not 1 <= asn <= 0xFFFFFFFF:
                        raise ValueError("Invalid origin ASN")
                    asns.append({"asn": asn, "holder": self._holder(asn)})
                value = {"status": "resolved" if asns else "not_routed", "prefix": prefix, "asns": asns,
                         "source": "RIPE RIS / RIPEstat"}
                ttl = 8*3600 if asns else 3600
            self._save(kind, address, value, ttl)
            with self.lock:
                self.completed += 1
        except Exception as exc:
            # Enrichment failures must not terminate a worker or affect receipt.
            error = f"{type(exc).__name__}: {str(exc)[:180]}"
            previous = self._cached(kind, address)
            value = dict(previous[0]) if previous else {}
            value.update(status="error", error=error)
            self._save(kind, address, value, 120)
            with self.lock:
                self.errors += 1
                self.last_error = error

    def _holder(self, asn):
        # Coalesce AS holder requests when several IPs belong to the same AS.
        with self.asn_lock:
            cached = self._cached("holder", str(asn))
            if cached and cached[1] > time.time():
                return cached[0].get("holder")
            try:
                holder = self.api_lookup("as-overview", f"AS{asn}").get("holder")
                holder = str(holder)[:300] if holder else None
                self._save("holder", str(asn), {"holder": holder}, 86400)
                return holder
            except Exception:
                # A holder-label failure does not discard a valid routing ASN.
                self._save("holder", str(asn), {"holder": None}, 120)
                return None

    def _request(self, endpoint, resource):
        if endpoint not in ("network-info", "as-overview"):
            raise ValueError("Unsupported lookup endpoint")
        with self.rate_lock:
            delay = max(0, self.next_request-time.monotonic())
            self.next_request = max(time.monotonic(), self.next_request)+1
        if self.stop.wait(delay):
            raise RuntimeError("Enrichment stopped")
        url = f"https://stat.ripe.net/data/{endpoint}/data.json?" + urlencode({"resource": resource})
        request = Request(url, headers={"User-Agent": "SimpleFlow/1.1 (network observability)", "Accept": "application/json"})
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read(1_000_000))
        if payload.get("status") != "ok" or not isinstance(payload.get("data"), dict):
            raise ValueError("Lookup service returned an unsuccessful response")
        return payload["data"]

    def status(self):
        with self.lock:
            return {"rdns": self.rdns, "asn": self.asn, "pending": len(self.pending), "completed": self.completed,
                    "errors": self.errors, "lastError": self.last_error, "provider": "RIPE RIS / RIPEstat",
                    "dnsCacheSeconds": 900, "bgpCacheSeconds": 28800}

    def close(self):
        self.stop.set()
        # Native DNS follows OS resolver timeouts. Do not block shutdown on it.
        # Keep the connection alive if a worker is still returning from I/O.
        for worker in self.workers:
            worker.join(timeout=.1)
        if not any(worker.is_alive() for worker in self.workers):
            self.db.close()
            self.closed = True
