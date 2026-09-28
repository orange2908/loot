---
title: "Async Port Scanner and Banner Grabber (No nmap)"
category: misc
subcategory: recon
type: script
tags: [port-scanner, banner-grabbing, asyncio, concurrency, port-knocking, python, recon, no-nmap, network-services, template]
summary: "A self-contained asyncio TCP port scanner with banner grabbing, concurrency control and an optional port-knock sequence, for when nmap is not available."
related: [net-scanning-fingerprinting, net-tcp-client-template, net-nmap-and-recon-cheatsheet]
---

## What this is

A pure-stdlib async port scanner you can drop on any box with Python 3.11 (a jump host, a container,
a restricted shell) when nmap is not installed. It scans a port list or range with a bounded number
of concurrent connections, grabs a banner from each open port (sending a light HTTP probe where
useful), and can fire a **port-knock** sequence first to open a knock-protected port. Includes an
offline self-test against a loopback listener.

## Usage

```bash
# Scan the top common ports on a host
python3 portscan.py 10.10.10.5

# Scan an explicit range with 500 concurrent connections
python3 portscan.py 10.10.10.5 --ports 1-10000 --concurrency 500

# Scan a comma list of ports
python3 portscan.py 10.10.10.5 --ports 22,80,443,8080,8443

# Knock 1111,2222,3333 (TCP SYN) then scan 22
python3 portscan.py 10.10.10.5 --knock 1111,2222,3333 --ports 22

# Adjust the connect timeout
python3 portscan.py 10.10.10.5 --ports 1-1000 --timeout 1.5

# Offline self-test (no target needed)
python3 portscan.py --selftest
```

## Script

```python
#!/usr/bin/env python3
"""Async TCP port scanner + banner grabber with concurrency control.

Pure stdlib (asyncio). Use when nmap is unavailable.

Features:
  - port list ("22,80,443") or range ("1-10000")
  - bounded concurrency via a semaphore
  - banner grab (server-speaks-first, with an HTTP probe fallback)
  - optional TCP port-knock sequence before scanning
  - offline --selftest
"""
from __future__ import annotations

import argparse
import asyncio
import sys

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    636, 993, 995, 1433, 1521, 2049, 3128, 3268, 3306, 3389, 5432, 5900, 5985,
    5986, 6379, 8000, 8080, 8443, 8888, 9000, 9200, 11211, 27017,
]

HTTP_PORTS = {80, 8000, 8080, 8888, 9000, 5000, 3000}


def parse_ports(spec: str | None) -> list[int]:
    """Turn '22,80' or '1-1000' (or None) into a sorted unique port list."""
    if not spec:
        return TOP_PORTS
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


async def knock(host: str, seq: list[int], timeout: float) -> None:
    """Fire a TCP-SYN knock sequence (connect attempts) in order."""
    for port in seq:
        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass  # knock ports usually refuse/drop; that is expected
        await asyncio.sleep(0.15)


async def grab_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                      port: int, timeout: float) -> str:
    """Read a server greeting; if silent and it looks like HTTP, send a request."""
    banner = b""
    try:
        banner = await asyncio.wait_for(reader.read(256), timeout=min(timeout, 2.0))
    except (asyncio.TimeoutError, ConnectionError, OSError):
        banner = b""
    if not banner and port in HTTP_PORTS:
        try:
            writer.write(b"GET / HTTP/1.0\r\n\r\n")
            await writer.drain()
            banner = await asyncio.wait_for(reader.read(256), timeout=min(timeout, 2.0))
        except (asyncio.TimeoutError, ConnectionError, OSError):
            banner = b""
    text = banner.decode("utf-8", "replace").strip()
    return text.splitlines()[0] if text else ""


async def scan_port(host: str, port: int, sem: asyncio.Semaphore,
                    timeout: float, results: list[tuple[int, str]]) -> None:
    """Connect to one port; on success record it and grab a banner."""
    async with sem:
        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        except (asyncio.TimeoutError, ConnectionError, OSError):
            return
        banner = await grab_banner(reader, writer, port, timeout)
        results.append((port, banner))
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


async def run_scan(host: str, ports: list[int], concurrency: int,
                   timeout: float, knock_seq: list[int]) -> list[tuple[int, str]]:
    """Optionally knock, then scan all ports with bounded concurrency."""
    if knock_seq:
        print(f"[*] knocking {knock_seq} ...")
        await knock(host, knock_seq, timeout)
        await asyncio.sleep(0.3)
    sem = asyncio.Semaphore(concurrency)
    results: list[tuple[int, str]] = []
    tasks = [scan_port(host, p, sem, timeout, results) for p in ports]
    await asyncio.gather(*tasks)
    return sorted(results)


async def _selftest() -> int:
    """Start a loopback listener with a banner, scan it, assert it is found."""
    banner = b"SELFTEST-SERVICE v1\r\n"

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(banner)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        await server.start_serving()
        results = await run_scan("127.0.0.1", [port, port + 1], 50, 2.0, [])
    found = {p for p, _ in results}
    assert port in found, f"scanner missed the open port {port}: {results}"
    got_banner = dict(results).get(port, "")
    assert "SELFTEST-SERVICE" in got_banner, got_banner
    print(f"[selftest] ok: found {port} banner={got_banner!r}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="async TCP port scanner + banner grabber")
    parser.add_argument("host", nargs="?", help="target host")
    parser.add_argument("--ports", help="'22,80' or '1-10000' (default: top common ports)")
    parser.add_argument("--concurrency", type=int, default=300)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--knock", help="comma list of knock ports to hit first")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()

    if args.selftest:
        return asyncio.run(_selftest())
    if not args.host:
        parser.print_help()
        return 1

    ports = parse_ports(args.ports)
    knock_seq = [int(x) for x in args.knock.split(",")] if args.knock else []
    print(f"[*] scanning {args.host}: {len(ports)} ports, concurrency={args.concurrency}")
    results = asyncio.run(run_scan(args.host, ports, args.concurrency, args.timeout, knock_seq))
    if not results:
        print("[-] no open ports found")
        return 0
    for port, banner in results:
        print(f"{port:>6}/tcp open   {banner}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Notes

- Concurrency is bounded by a semaphore so you do not exhaust file descriptors or trip rate limits;
  drop `--concurrency` on a flaky VPN.
- Banner grabbing is best-effort: many services stay silent until spoken to, so the HTTP probe only
  fires on likely web ports. Extend `HTTP_PORTS`/`grab_banner` for other protocols.
- The knock sequence uses plain TCP connect attempts (SYN); for UDP-based knocking you would send
  datagrams instead.
- This is a connect() scanner (no raw sockets), so it needs no root and works through most restricted
  shells -- but it is slower than nmap SYN scanning and will show up in connection logs.
