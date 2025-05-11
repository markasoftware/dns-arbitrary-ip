import abc
from ipaddress import IPv4Address
import logging
import socket

from lib_dns import DnsFormatError, DnsMessage, DnsQuestion, DnsResource, DnsResourceDataA, OpCode, QueryResponse, RCode, ResourceClass, ResourceType, domains_equal

_LOGGER = logging.getLogger(__name__)

class DnsServer(abc.ABC):
    """A DNS server that covers most common cases; subclasses implement `compute_response`. To use, call `serve`"""

    def compute_error_response(self, query: DnsMessage, rcode: RCode) -> DnsMessage:
        """Optionally override to change the error response"""
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


    @abc.abstractmethod
    def compute_response(self, query: DnsMessage, source_ip: IPv4Address, source_port: int) -> DnsMessage:
        ...

    def listen(self, host: str, port: int) -> None:
        assert isinstance(port, int), "port must actually be an integer" # rookie mistake

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, port))

        print(f"Listening on {host}:{port}")

        while True:
            try:
                data, source_addr = sock.recvfrom(512)
                source_ip = IPv4Address(source_addr[0])
                source_port: int = source_addr[1]

                try:
                    query = DnsMessage.parse(data)
                    response = self.compute_response(query, source_ip=source_ip, source_port=source_port)
                except DnsFormatError as e:
                    _LOGGER.warning(f"DNS format error: {e}")
                    response = self.compute_error_response(query, rcode=RCode.FORMAT_ERROR)
                except Exception as e:
                    _LOGGER.warning(f"Error, sending error response: {e}")
                    response = self.compute_error_response(query, rcode=RCode.SERVER_FAILURE)

                sock.sendto(response.serialize(), source_addr)
            except Exception as e:
                _LOGGER.error(f"Error not handled gracefully! {e}")

class DnsPerQuestionServer(DnsServer, abc.ABC):
    """
    A DNS server where the custom part of the implementation only needs to work on a
    question-by-question basis. Whereas the base DnsServer requires subclasses to implement
    compute_response of type DnsMessage->DnsMessage, this class only requires a
    DnsQuestion->DnsResource and handles looping over the questions automatically.
    """

    @abc.abstractmethod
    def compute_answer(self, question: DnsQuestion, source_ip: IPv4Address, source_port: int) -> DnsResource | None:
        """Return the response to the question, or None to indicate it wasn't found."""
        # TODO I'm pretty sure this isn't the right way to actually handle some domains being found
        # and some not being found -- I'm pretty sure you're supposed to somehow explicitly indicate
        # which domains are missing rather than still acknowledging them int he Question section of
        # the response but then just omitting them from the answers?
        ...

    def compute_response(self, query: DnsMessage, source_ip: IPv4Address, source_port: int) -> DnsMessage:
        answers = [answer for answer in [self.compute_answer(q, source_ip, source_port) for q in query.questions] if answer is not None]

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

class DnsPerQuestionSimpleServer(DnsPerQuestionServer, abc.ABC):
    """Like DnsPerQuestionServer, but only supports A records and also has a "base domain" that it checks that all requests are under."""
    def __init__(self, base_domain: list[str], ttl: int = 86400) -> None:
        self.base_domain: list[str] = base_domain
        self.ttl: int = ttl

    @abc.abstractmethod
    def compute_simple_answer(self, query_domain: list[str], source_ip: IPv4Address, source_port: int) -> IPv4Address | None:
        ...

    def compute_answer(self, question: DnsQuestion, source_ip: IPv4Address, source_port: int) -> DnsResource | None:
        if question.q_type != ResourceType.A.value or question.q_class != ResourceClass.IN.value:
            _LOGGER.debug("Question is not A/IN, skipping")
            return None
        if not domains_equal(question.name[-len(self.base_domain):], self.base_domain):
            _LOGGER.debug("Question name is not under base domain, skipping")
            return None

        result_ip = self.compute_simple_answer(question.name[:-len(self.base_domain)], source_ip=source_ip, source_port=source_port)
        if result_ip is None:
            return None

        return DnsResource(
            name=question.name,
            r_type=ResourceType.A.value,
            r_class=ResourceClass.IN.value,
            ttl=self.ttl,
            data=DnsResourceDataA(result_ip),
        )
