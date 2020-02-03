__all__ = [
    "AttestationResult", "DomainInfo", "KeyTriple", "MessageType",
    "SendMethod", "AccessMethod"
]

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


class SendMethod(str, enum.Enum):
    # shared with other clients
    shared = "shared"
    # only this client has access
    private = "private"
    # don't leave a trace who sent the email
    stealth = "stealth"

    def __str__(self):
        # output value instead of member name
        return self.value


class AccessMethod(str, enum.Enum):
    # peek message from cache but don't mark as read
    peek = "peek"
    # view message from cache and mark as read
    view = "view"
    # bypass cache
    bypass = "bypass"

    def __str__(self):
        # output value instead of member name
        return self.value
