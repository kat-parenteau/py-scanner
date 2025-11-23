#!/usr/bin/env python3
"""
py-scanner-safe.py
Safe local-network scanner: allows only localhost or private IP ranges.
Usage: python py-scanner-safe.py [target]
If no target provided, defaults to 127.0.0.1 (localhost).
"""

import socket
import sys
import nmap
import ipaddress
import argparse

PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # localhost range
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),          # IPv6 localhost
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique local addresses
]

def is_private_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for net in PRIVATE_NETWORKS:
        if ip in net:
            return True
    return False

def resolve_target(target):
    """Resolve a hostname to a list of IP strings (IPv4/IPv6)."""
    try:
        infos = socket.getaddrinfo(target, None)
        ips = sorted({info[4][0] for info in infos})
        return ips
    except socket.gaierror:
        return []

def main():
    p = argparse.ArgumentParser()
    p.add_argument("target", nargs="?", default="127.0.0.1",
                   help="IP or hostname to scan (defaults to localhost)")
    p.add_argument("-p", "--ports", default="1-1024", help="Port range (default 1-1024)")
    p.add_argument("--whitelist-file", help="Optional path to a file with additional allowed IPs (one per line)")
    args = p.parse_args()

    # Resolve and validate
    ips = resolve_target(args.target)
    if not ips:
        print(f"[ERROR] Could not resolve target: {args.target}")
        sys.exit(2)

    # Optionally load whitelist
    extra_allowed = set()
    if args.whitelist_file:
        try:
            with open(args.whitelist_file) as fh:
                for line in fh:
                    s = line.strip()
                    if s:
                        extra_allowed.add(s)
        except Exception as e:
            print(f"[WARN] Could not read whitelist file: {e}")

    # Check each resolved IP is acceptable
    for ip in ips:
        if ip in extra_allowed:
            continue
        if not is_private_ip(ip):
            print(f"[ERROR] Refusing to scan public IP {ip}. Only localhost/private ranges allowed.")
            sys.exit(3)

    # All checks passed -> perform scan locally
    scanner = nmap.PortScanner()
    target_ip = ips[0]
    print(f"[INFO] Scanning {args.target} -> {target_ip} (ports {args.ports})")
    try:
        scanner.scan(target_ip, args.ports, '-sS -sV')
    except Exception as e:
        print(f"[ERROR] Nmap scan failed: {e}")
        sys.exit(4)

    # Print results (open ports only)
    for host in scanner.all_hosts():
        print(f"\nHost: {host} ({scanner[host].hostname()}) State: {scanner[host].state()}")
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in sorted(ports):
                port_data = scanner[host][proto][port]
                if port_data['state'] == 'open':
                    svc = port_data.get('name', 'unknown')
                    ver = port_data.get('version', '')
                    print(f"  Open {proto}/{port} - {svc} {ver}")

if __name__ == "__main__":
    main()
