__all__ = ["load_public_key", "load_priv_key"]

import getpass

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_pem_public_key
)
from cryptography.x509 import load_pem_x509_certificate

defbackend = default_backend()


def load_priv_key(data, func=lambda: getpass("Enter passphrase:")):
    key = None
    backend = None
    pw = None
    if isinstance(data, str):
        data = data.encode("utf8")
    try:
        key = load_pem_private_key(data, None, defbackend)
    except ValueError:
        pass
    except TypeError:
        backend = load_pem_private_key
    if backend:
        while not key:
            try:
                key = backend(
                    data,
                    func,
                    defbackend
                )
            except TypeError:
                pass
    return key, pw


def load_public_key(key):
    if isinstance(key, str):
        key = key.encode("utf8")
    elif hasattr(key, "public_bytes"):
        return key
    elif hasattr(key, "public_key"):
        return key.public_key()
    if isinstance(key, str):
        key = key.encode("utf8")
    try:
        return load_pem_x509_certificate(
            key, defbackend
        ).public_key()
    except ValueError:
        try:
            return load_pem_public_key(
                key, defbackend
            )
        except ValueError:
            raise
