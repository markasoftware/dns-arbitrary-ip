#!/usr/bin/env python3

from __future__ import annotations

import argparse
from ipaddress import IPv4Address
import logging
import socket

from lib_dns import DnsFormatError, DnsMessage, DnsQuestion, DnsResource, DnsResourceDataA, OpCode, QueryResponse, RCode, ResourceClass, ResourceType, domains_equal

_LOGGER = logging.getLogger(__name__)

def parse_english_number(in_english: str) -> int | None:
    english_digits = in_english.split("-")
    if len(english_digits) > 3:
        return None

    english_to_int = {"zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9}

    num = 0
    for i, english_digit in enumerate(reversed(english_digits)):
        digit = english_to_int.get(english_digit)
        if digit is None:
            return None
        num += 10**i * digit
    return num

def compute_response(query: DnsMessage, base_domain: list[str], reverse: bool) -> DnsMessage:
    def question_to_answer(question: DnsQuestion) -> DnsResource | None:
        if question.q_type != ResourceType.A.value or question.q_class != ResourceClass.IN.value:
            _LOGGER.debug("Question is not A/IN, skipping")
            return None
        if len(question.name) < len(base_domain) + 4:
            _LOGGER.debug("Question name not long enough, skipping")
            return None
        if not domains_equal(question.name[4:], base_domain):
            _LOGGER.debug("Question name is not under base domain, skipping")
            return None

        ip_labels = [qn.lower() for qn in question.name[:4]] # notice the .lower()!
        if reverse:
            ip_labels.reverse()

        ip_int_labels: list[int] = []
        for label in ip_labels:
            int_label: int | None
            try:
                int_label = int(label)
            except ValueError:
                int_label = parse_english_number(label)
                if int_label is None:
                    _LOGGER.debug(f"Question label was neither numeric nor english, skipping: '{label}'")
                    return None

            if not (0 <= int_label <= 0xFF):
                _LOGGER.debug("Question contains an IP part out of the [0, 0xFF] range, skipping")
                return None
            ip_int_labels.append(int_label)

        ip = IPv4Address(bytes(ip_int_labels))

        return DnsResource(
            name=question.name,
            r_type=ResourceType.A.value,
            r_class=ResourceClass.IN.value,
            ttl=86400,
            data=DnsResourceDataA(ip),
        )
    
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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-domain", required=True,
                        help="Domain under which the ip-specific domains live. Eg, if ip.markasoftware.com, then 192.168.0.1.ip.markasoftware.com will work")
    parser.add_argument("--reverse", action="store_true",
                        help="If set, then IPs will be reversed, eg 1.0.168.192.markasoftware.com would resolve to 192.168.0.1.")
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", default="53")
    args = parser.parse_args()

    base_domain = args.base_domain.split(".")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.listen_host, int(args.listen_port)))

    print(f"Listening on {args.listen_host}:{args.listen_port}")

    while True:
        try:
            data, addr = sock.recvfrom(512)

            try:
                query = DnsMessage.parse(data)
                response = compute_response(query=query, base_domain=base_domain, reverse=args.reverse)
            except DnsFormatError as e:
                _LOGGER.warning(f"DNS format error: {e}")
                response = compute_error_response(query, rcode=RCode.FORMAT_ERROR)
            except Exception as e:
                _LOGGER.warning(f"Error, sending error response: {e}")
                response = compute_error_response(query, rcode=RCode.SERVER_FAILURE)

            sock.sendto(response.serialize(), addr)
        except Exception as e:
            _LOGGER.error(f"Error not handled gracefully! {e}")

if __name__ == "__main__":
    logging.basicConfig()
    main()
