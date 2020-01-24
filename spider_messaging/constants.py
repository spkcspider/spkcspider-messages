__all__ = ("AttestationResult", "DomainInfo", "KeyTriple", "MessageType")

from collections import namedtuple
import enum


DomainInfo = namedtuple(
    'DomainInfo',
    ['id', 'attestation', 'hash_algo']
)

KeyTriple = namedtuple(
    'KeyTriple',
    ['hash', 'key', 'signature']
)


class AttestationResult(enum.IntEnum):
    success = 0
    partial_success = 1
    domain_unknown = 2
    error = 3


class MessageType(str, enum.Enum):
    # encrypted redirect
    redirect = "redirect"
    # message object
    message = "message"
    # email object (html, more powerful)
    email = "email"
    # file object
    file = "file"

    def __str__(self):
        # output value instead of member name
        return self.value

    def __bytes__(self):
        # for headers
        return self.value.encode("ascii")
