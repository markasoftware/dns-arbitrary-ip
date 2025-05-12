#!/usr/bin/env python3

from __future__ import annotations

import argparse
from ipaddress import IPv4Address
import logging
import shutil
import subprocess

from server_common import DnsPerQuestionSimpleServer

_LOGGER = logging.getLogger(__name__)

def check_dig_exists() -> None:
    if shutil.which("dig") is None:
        raise RuntimeError("Missing `dig` -- needed for this dns server")

def reverse_dns_lookup(address: IPv4Address, public_dns_server: IPv4Address, public_dns_server_port: int) -> str:
    # I don't think we actually need `+norrcomments` but it can't hurt
    return subprocess.check_output(["dig", f"@{public_dns_server.exploded}", f"-p{public_dns_server_port}", "+nocomments", "+noquestion", "+nocmd", "+nostats", "+norrcomments", "-x", address.exploded, "PTR", "-x", address.exploded, "SOA"]).decode("ascii").lower()

class DnsTargetedSwitcherooServer(DnsPerQuestionSimpleServer):
    def __init__(self, base_domain: list[str], ip_mappings: list[tuple[str, IPv4Address]], fallback_ip: IPv4Address, public_dns_server: IPv4Address, public_dns_server_port: int) -> None:
        super().__init__(base_domain)
        self.ip_mappings: list[tuple[str, IPv4Address]] = ip_mappings
        self.fallback_ip: IPv4Address = fallback_ip
        self.public_dns_server: IPv4Address = public_dns_server
        self.public_dns_server_port: int = public_dns_server_port

    def compute_simple_answer(self, query_domain: list[str], source_ip: IPv4Address, source_port: int) -> IPv4Address | None:
        reverse_dns_str = reverse_dns_lookup(source_ip, self.public_dns_server, self.public_dns_server_port)
        _LOGGER.debug(f"Reverse DNS lookup for {source_ip}:\n{reverse_dns_str}")
        for needle, ip in self.ip_mappings:
            if needle.lower() in reverse_dns_str:
                return ip
        return self.fallback_ip
        
def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-domain", required=True,
                        help="Domain name under which the Special Domains will live.")
    parser.add_argument("--ip-mapping", action="append", default=[],
                        help="Specify multiple times. Each entry should be in the format SUBSTRING,8.8.8.8 which will mean that if either the PTR or SOA reverse lookup records for an IP contains SUBSTRING, the given IP will be returned")
    parser.add_argument("--fallback-ip", required=True,
                        help="Specify IP to return if none of the IP mappings match")
    parser.add_argument("--public-dns-server", default="1.1.1.1",
                        help="DNS server to use for reverse lookups")
    parser.add_argument("--public-dns-server-port", default="53",
                        help="Port to use for reverse lookups")
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", default="53")
    args = parser.parse_args()

    base_domain: list[str] = args.base_domain.split(".")
    ip_mappings: list[tuple[str, IPv4Address]] = []
    for ip_mapping_str in args.ip_mapping:
        needle, ip_str = ip_mapping_str.split(",")
        ip_mappings.append((needle, IPv4Address(ip_str)))
    fallback_ip = IPv4Address(args.fallback_ip)
    # Parsing as IP just to ensure it's the correct format
    public_dns_server = IPv4Address(args.public_dns_server)
    public_dns_server_port = int(args.public_dns_server_port)

    check_dig_exists()

    server = DnsTargetedSwitcherooServer(base_domain=base_domain, ip_mappings=ip_mappings, fallback_ip=fallback_ip, public_dns_server=public_dns_server, public_dns_server_port=public_dns_server_port)
    server.listen(args.listen_host, int(args.listen_port))

if __name__ == "__main__":
    logging.basicConfig()
    main()
