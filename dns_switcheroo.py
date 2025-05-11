#!/usr/bin/env python3

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from ipaddress import IPv4Address
from functools import lru_cache
import logging
import typing as ty

from lib_dns import DnsQuestion, DnsResource, DnsResourceDataA, ResourceClass, ResourceType, domains_equal
from server_common import DnsPerQuestionServer

_LOGGER = logging.getLogger(__name__)

class DnsSwitcherooServer(DnsPerQuestionServer):
    def __init__(self, base_domain: list[str], ips: list[IPv4Address]) -> None:
        self.base_domain: list[str] = base_domain

        @lru_cache(maxsize=2048)
        def get_ephemeral_domain(domain: str) -> EphemeralDomain:
            """A bit of a hack -- we abuse @lru_cache because we actually mutate the output. `domain` arg is only the label before the base domain."""
            return EphemeralDomain(remaining_ips=[IPv4Address(ip) for ip in ips])

        self.get_ephemeral_domain: ty.Callable[[str], EphemeralDomain] = get_ephemeral_domain

    def compute_answer(self, question: DnsQuestion, source_ip: IPv4Address, source_port: int) -> DnsResource | None:
        def ip_to_resource(ip: IPv4Address) -> DnsResource:
            return DnsResource(
                name=question.name,
                r_type=ResourceType.A.value,
                r_class=ResourceClass.IN.value,
                ttl=86400,
                data=DnsResourceDataA(ip),
            )

        if question.q_type != ResourceType.A.value or question.q_class != ResourceClass.IN.value:
            _LOGGER.debug("Question is not A/IN, skipping")
            return None
        if len(question.name) != len(self.base_domain) + 1:
            _LOGGER.debug("Question name not the right length, skipping")
            return None
        if not domains_equal(question.name[1:], self.base_domain):
            _LOGGER.debug("Question name is not under base domain, skipping")
            return None

        ephemeral_label = question.name[0].lower() # notice the .lower()!
        ephemeral_domain = self.get_ephemeral_domain(ephemeral_label)

        already_assigned_ip = ephemeral_domain.assigned_ips.get(source_ip)
        if already_assigned_ip:
            _LOGGER.debug(f"IP already assigned for {source_ip} on subdomain {ephemeral_label}: {already_assigned_ip}")
            return ip_to_resource(already_assigned_ip)

        assert ephemeral_domain.remaining_ips, "ephemeral_domain.remaining_ips should never be empty"

        if len(ephemeral_domain.remaining_ips) == 1:
            _LOGGER.debug(f"Only one IP left on subdomain {ephemeral_label} and source {source_ip} is unknown: {already_assigned_ip}")
            return ip_to_resource(ephemeral_domain.remaining_ips[0])

        result_ip = ephemeral_domain.remaining_ips[0]
        ephemeral_domain.remaining_ips = ephemeral_domain.remaining_ips[1:]
        ephemeral_domain.assigned_ips[source_ip] = result_ip
        _LOGGER.debug(f"Source IP {source_ip} on subdomain {ephemeral_label} is now assigned to: {result_ip}")
        return ip_to_resource(result_ip)

@dataclass
class EphemeralDomain:
    remaining_ips: list[IPv4Address]
    assigned_ips: dict[IPv4Address, IPv4Address] = field(default_factory=dict)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-domain", required=True,
                        help="Domain name under which the Special Domains will live.")
    parser.add_argument("--ip", required=True, action="append",
                        help="Specify multiple times. The first IP specified will be returned to the first IP to request each subdomain, the second to the second, the third to the third, etc. The last specified IP will be returned to all remaining requests.")
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", default="53")
    args = parser.parse_args()

    base_domain = args.base_domain.split(".")
    ips = [IPv4Address(ip) for ip in args.ip]

    server = DnsSwitcherooServer(base_domain=base_domain, ips=ips)
    server.listen(args.listen_host, int(args.listen_port))

if __name__ == "__main__":
    logging.basicConfig()
    main()
