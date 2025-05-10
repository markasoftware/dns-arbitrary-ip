from __future__ import annotations

import abc
from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv4Address
import logging
import struct

_LOGGER = logging.getLogger(__name__)

class DnsFormatError(Exception):
    pass

class DnsNotImplementedError(Exception):
    pass

class QueryResponse(Enum):
    QUERY = 0
    RESPONSE = 1

class OpCode(Enum):
    STANDARD_QUERY = 0
    INVERSE_QUERY = 1
    SERVER_STATUS = 2

class RCode(Enum):
    NO_ERROR = 0
    FORMAT_ERROR = 1
    SERVER_FAILURE = 2
    NAME_ERROR = 3
    NOT_IMPLEMENTED = 4
    REFUSED = 5

class ResourceType(Enum):
    A = 1

class ResourceClass(Enum):
    IN = 1

DomainName = list[str]  # labels

@dataclass
class DnsQuestion:
    name: DomainName
    q_type: int
    q_class: int

@dataclass
class DnsResource:
    # the r_ prefixes are not standard, but to avoid "type" and "class" python reserved words
    name: DomainName
    r_type: int
    r_class: int
    ttl: int
    data: DnsResourceData

class DnsResourceData(abc.ABC):
    @abc.abstractmethod
    def to_bytes(self) -> bytes:
        ...

@dataclass
class DnsResourceDataUnknown(DnsResourceData):
    r_data: bytes

    @staticmethod
    def try_from_bytes(r_type: int, r_class: int, msg: bytes) -> DnsResourceDataUnknown:
        return DnsResourceDataUnknown(msg)

    def to_bytes(self) -> bytes:
        return self.r_data

@dataclass
class DnsResourceDataA(DnsResourceData):
    ip_addr: IPv4Address

    @staticmethod
    def try_from_bytes(r_type: int, r_class: int, msg: bytes) -> DnsResourceDataA | None:
        if r_type != ResourceType.A.value or r_type != ResourceClass.IN.value:
            return None

        if len(msg) != 4:
            raise DnsFormatError(f"Length of A record data must be 4 bytes exactly, but was {len(msg)}")
        ip_bytes = struct.unpack("4s", msg)
        return DnsResourceDataA(IPv4Address(ip_bytes))

    def to_bytes(self) -> bytes:
        return struct.pack("4s", self.ip_addr.packed)

dns_resource_data_classes = [DnsResourceDataA, DnsResourceDataUnknown]

@dataclass
class DnsMessage:
    transaction_id: int
    query_response: QueryResponse
    opcode: OpCode
    authoritative_answer: bool
    truncation: bool
    recursion_desired: bool
    recursion_available: bool
    z: int
    rcode: RCode
    questions: list[DnsQuestion]
    answers: list[DnsResource]
    authorities: list[DnsResource]
    additionals: list[DnsResource]

    @staticmethod
    def parse(orig_msg: bytes) -> DnsMessage:
        msg = orig_msg

        def bsplit(msg: bytes, at: int) -> tuple[bytes, bytes]:
            return msg[:at], msg[at:]

        def bsplit_1(msg: bytes) -> tuple[int, bytes]:
            return msg[0], msg[1:]

        def parse_domain_name(msg: bytes) -> tuple[DomainName, bytes]:
            """Parse the domain name starting at buf, return it and the unparsed bytes"""
            labels = []

            label_length, msg = bsplit_1(msg)
            while label_length != 0:
                _LOGGER.debug(f"Label length: {label_length}")
                # dns compression: can refer to any location in the message
                if (label_length >> 6) == 0b11:
                    _LOGGER.debug("Compressed domain name!")
                    label_length_2, msg = bsplit_1(msg)
                    offset = ((label_length & 0b111111) << 8) + label_length_2
                    pointed_to_domain_name, _ = parse_domain_name(orig_msg[offset:])
                    labels += pointed_to_domain_name
                    # an offset must be the last entry in a domain, so we're done
                    return labels, msg

                label_body, msg = bsplit(msg, label_length)
                labels.append(label_body.decode('ascii'))
                label_length, msg = bsplit_1(msg)
            return labels, msg

        if len(msg) < 12:
            raise DnsFormatError("Message too short")
        header, msg = bsplit(msg, 12)
        transaction_id, flags_byte_1, flags_byte_2, question_count, answer_count, authority_count, additional_count = struct.unpack("!HBBHHHH", header)
        recursion_desired = bool((flags_byte_1) & 0b1)
        truncation = bool((flags_byte_1 >> 1) & 0b1)
        authoritative_answer = bool((flags_byte_1 >> 2) & 0b1)
        opcode = OpCode((flags_byte_1 >> 3) & 0b1111)
        query_response = QueryResponse((flags_byte_1 >> 7) & 0b1)

        rcode = RCode(flags_byte_2 & 0b1111)
        z = (flags_byte_2 >> 4) & 0b111  # modern day Z contains AD bit and stuff, let's just ignore
        recursion_available = bool((flags_byte_2 >> 7) & 0b1)

        _LOGGER.debug("parsing questions")
        questions = []
        for i in range(question_count):
            name, msg = parse_domain_name(msg)

            typeclass, msg = bsplit(msg, 4)
            q_type, q_class = struct.unpack("!HH", typeclass)

            questions.append(DnsQuestion(name=name, q_type=q_type, q_class=q_class))

        def parse_resources(how_many: int, msg: bytes) -> tuple[list[DnsResource], bytes]:
            resources = []
            for i in range(how_many):
                name, msg = parse_domain_name(msg)
                header, msg = bsplit(msg, 10)
                r_type, r_class, ttl, r_dlength = struct.unpack("!HHLH", header)

                r_data, msg = bsplit(msg, r_dlength)
                for dns_resource_data_class in dns_resource_data_classes:
                    downcasted_data = dns_resource_data_class.try_from_bytes(r_type, r_class, r_data) # type: ignore[attr-defined]
                    if downcasted_data:
                        break
                assert downcasted_data

                resources.append(DnsResource(name=name, r_type=r_type, r_class=r_class, ttl=ttl, data=downcasted_data))
            return resources, msg

        _LOGGER.debug("parsing answers")
        answers, msg = parse_resources(answer_count, msg)
        _LOGGER.debug("parsing authorities")
        authorities, msg = parse_resources(authority_count, msg)
        _LOGGER.debug("parsing additionals")
        additionals, msg = parse_resources(additional_count, msg)

        return DnsMessage(
            transaction_id=transaction_id,
            query_response=query_response,
            opcode=opcode,
            authoritative_answer=authoritative_answer,
            truncation=truncation,
            recursion_desired=recursion_desired,
            recursion_available=recursion_available,
            z=z,
            rcode=rcode,
            questions=questions,
            answers=answers,
            authorities=authorities,
            additionals=additionals,
        )

    def serialize(self) -> bytes:
        msg = bytes()

        flags_byte_1 = (int(self.recursion_desired) & 0b1) | \
            ((int(self.truncation) & 0b1) << 1) | \
            ((int(self.authoritative_answer) & 0b1) << 2) | \
            ((self.opcode.value & 0b1111) << 3) | \
            ((self.query_response.value & 0b1) << 7)
        flags_byte_2 = (self.rcode.value & 0b1111) | \
            ((self.z & 0b111) << 4) | \
            ((int(self.recursion_available) & 0b1) << 7)
        msg += struct.pack("!HBBHHHH", self.transaction_id, flags_byte_1, flags_byte_2, len(self.questions), len(self.answers), len(self.authorities), len(self.additionals))

        def serialize_domain_name(labels: list[str]) -> bytes:
            result = bytes()
            for label in labels:
                result += struct.pack("B", len(label))
                result += label.encode("ascii")
            result += struct.pack("B", 0)
            return result

        for question in self.questions:
           msg += serialize_domain_name(question.name)
           msg += struct.pack("!HH", question.q_type, question.q_class)

        def serialize_resources(resources: list[DnsResource]) -> bytes:
            msg = bytes()
            for resource in resources:
                data_bytes = resource.data.to_bytes()

                msg += serialize_domain_name(resource.name)
                msg += struct.pack("!HHLH", resource.r_type, resource.r_class, resource.ttl, len(data_bytes))
                msg += resource.data.to_bytes()
            return msg

        msg += serialize_resources(self.answers)
        msg += serialize_resources(self.authorities)
        msg += serialize_resources(self.additionals)

        return msg

def domains_equal(domain_1: list[str], domain_2: list[str]) -> bool:
    return [dn1.lower() for dn1 in domain_1] == [dn2.lower() for dn2 in domain_2]

def domain_label_equal(label_1: str, label_2: str) -> bool:
    return label_1.lower() == label_2.lower()
