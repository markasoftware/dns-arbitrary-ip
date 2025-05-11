#!/usr/bin/env python3

from __future__ import annotations

import argparse
from ipaddress import IPv4Address
import logging

from server_common import DnsPerQuestionSimpleServer

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

class DnsArbitraryIpServer(DnsPerQuestionSimpleServer):
    def __init__(self, base_domain: list[str], reverse: bool) -> None:
        super().__init__(base_domain)
        self.reverse: bool = reverse

    def compute_simple_answer(self, query_domain: list[str], source_ip: IPv4Address, source_port: int) -> IPv4Address | None:
        if len(query_domain) < 4:
            _LOGGER.debug("Question name not long enough, skipping")
            return None

        ip_labels = [qn.lower() for qn in query_domain] # notice the .lower()!
        if self.reverse:
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

        return IPv4Address(bytes(ip_int_labels))

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

    server = DnsArbitraryIpServer(base_domain, args.reverse)
    server.listen(host=args.listen_host, port=int(args.listen_port))

if __name__ == "__main__":
    logging.basicConfig()
    main()
