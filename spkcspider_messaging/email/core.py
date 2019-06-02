__all__ = ["load_priv_key"]

from getpass import getpass

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_der_private_key
)


def load_priv_key(data):
    key = None
    backend = None
    pw = None
    defbackend = default_backend()
    try:
        key = load_pem_private_key(data, None)
    except ValueError:
        pass
    except TypeError:
        key = load_pem_private_key(data, None, defbackend)
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
