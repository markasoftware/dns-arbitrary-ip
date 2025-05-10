#!/usr/bin/env python3

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from ipaddress import IPv4Address
from functools import lru_cache
import logging
import socket
import typing as ty

from lib_dns import DnsFormatError, DnsMessage, DnsQuestion, DnsResource, DnsResourceDataA, OpCode, QueryResponse, RCode, ResourceClass, ResourceType, domains_equal

_LOGGER = logging.getLogger(__name__)

def compute_response(query: DnsMessage, get_ephemeral_domain: ty.Callable[[str], EphemeralDomain], base_domain: list[str], source_ip: IPv4Address) -> DnsMessage:
    assert isinstance(source_ip, IPv4Address), "type error"

    def question_to_answer(question: DnsQuestion) -> DnsResource | None:
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
        if len(question.name) != len(base_domain) + 1:
            _LOGGER.debug("Question name not the right length, skipping")
            return None
        if not domains_equal(question.name[1:], base_domain):
            _LOGGER.debug("Question name is not under base domain, skipping")
            return None

        ephemeral_label = question.name[0].lower() # notice the .lower()!
        ephemeral_domain = get_ephemeral_domain(ephemeral_label)

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

    answers: list[DnsResource] = list(filter(lambda x: x is not None, map(question_to_answer, query.questions))) # type: ignore[arg-type]

    return DnsMessage(
        transaction_id = query.transaction_id,
        query_response = QueryResponse.RESPONSE,
        opcode = OpCode.STANDARD_QUERY,
        authoritative_answer = True,
        truncation = False,
        recursion_desired = False,
        recursion_available = False,
        z = 0,
        rcode = RCode.NO_ERROR if len(answers) > 0 else RCode.NAME_ERROR,
        questions = query.questions,
        answers = answers,
        authorities = [],
        additionals = [],
    )


def compute_error_response(query: DnsMessage, rcode: RCode) -> DnsMessage:
    return DnsMessage(
        transaction_id=query.transaction_id,
        query_response=QueryResponse.RESPONSE,
        opcode=OpCode.STANDARD_QUERY,
        authoritative_answer=False,
        truncation=False,
        recursion_desired=False,
        recursion_available=False,
        z=0,
        rcode=rcode,
        questions=query.questions,
        answers=[],
        authorities=[],
        additionals=[],
    )

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

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.listen_host, int(args.listen_port)))

    @lru_cache(maxsize=2048)
    def ephemeral_domain(domain: str) -> EphemeralDomain:
        """A bit of a hack -- we abuse @lru_cache because we actually mutate the output. `domain` arg is only the label before the base domain."""
        return EphemeralDomain(remaining_ips=[IPv4Address(ip) for ip in args.ip])


    print(f"Listening on {args.listen_host}:{args.listen_port}")

    while True:
        try:
            data, source_addr = sock.recvfrom(512) # this addr, port prob only works for IPv4
            source_ip = IPv4Address(source_addr[0]) # conscious choice not to include the source port as part of the logical source address

            try:
                query = DnsMessage.parse(data)
                response = compute_response(query=query, base_domain=base_domain, source_ip=source_ip, get_ephemeral_domain=ephemeral_domain)
            except DnsFormatError as e:
                _LOGGER.warning(f"DNS format error: {e}")
                response = compute_error_response(query, rcode=RCode.FORMAT_ERROR)
            except Exception as e:
                _LOGGER.warning(f"Error, sending error response: {e}")
                response = compute_error_response(query, rcode=RCode.SERVER_FAILURE)

            sock.sendto(response.serialize(), source_addr)
        except Exception as e:
            _LOGGER.error(f"Error not handled gracefully! {e}")

if __name__ == "__main__":
    logging.basicConfig()
    main()
