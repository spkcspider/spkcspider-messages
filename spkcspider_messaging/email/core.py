__all__ = ["load_priv_key", "startTLSProtocol", "startTLSFactory"]

from getpass import getpass

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import (
    load_pem_x509_certificate, load_der_x509_certificate
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_der_private_key,
    load_pem_public_key, load_der_public_key
)


from twisted.internet import protocol
from twisted.protocols.basic import LineReceiver


def load_priv_key(data):
    key = None
    backend = None
    pw = None
    defbackend = default_backend()
    try:
        key = load_pem_private_key(data, None, defbackend)
    except ValueError:
        pass
    except TypeError:
        backend = load_pem_private_key
    if not backend:
        try:
            key = load_der_private_key(data, None, defbackend)
        except ValueError:
            pass
        except TypeError:
            backend = load_der_private_key
    if backend:
        while not key:
            try:
                key = load_der_private_key(
                    data,
                    getpass("Enter passphrase:"),
                    defbackend
                )
            except TypeError:
                pass

    return key, pw


def load_public_key(key):
    defbackend = default_backend()
    if isinstance(key, str):
        key = key.encode("utf8")
    try:
        return load_pem_x509_certificate(
            key, defbackend
        ).public_key()
    except ValueError:
        try:
            return load_der_x509_certificate(
                key, defbackend
            ).public_key()
        except ValueError:
            try:
                return load_pem_public_key(
                    key, defbackend
                ).public_key()
            except ValueError:
                try:
                    return load_der_public_key(
                        key, defbackend
                    ).public_key()
                except ValueError:
                    raise


class startTLSProtocol(LineReceiver):
    wrapped_protocol = None

    def __init__(self, wrapped_protocol):
        self.wrapped_protocol = wrapped_protocol

    def lineReceived(self, line):
        if line == "STARTTLS" and self.factory:
            self.sendLine('READY')
            self.transport.startTLS(self.factory.cert_options)
            self.setRawMode()
        elif not self.factory.encryption_required:
            self.setRawMode()
            return self.rawDataReceived(line)
        else:
            self.transport.loseConnection()

    def rawDataReceived(self, data):
        return self.wrapped_protocol.dataReceived(data)

    def lineLengthExceeded(self, line):
        if not self.factory.encryption_required:
            self.transport.loseConnection()
        else:
            self.setRawMode()
            return self.rawDataReceived(line)


class startTLSFactory(protocol.Factory):
    protocol = None
    encryption_required = False
    cert_options = None

    def buildProtocol(self, wrapped_protocol):
        p = startTLSProtocol(wrapped_protocol)
        p.factory = self
        return p
