#! /usr/bin/env python3

import os
import argparse
import logging
import sys
# import base64
from datetime import datetime as dt
from datetime import timedelta as td

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from spider_messaging.utils.keys import load_priv_key

logger = logging.getLogger(__name__)

parser = argparse.ArgumentParser(
    description='Store or load message manually'
)
parser.add_argument(
    '--key', action='store', dest="key",
    default="key.priv", help='Private Key'
)
parser.add_argument(
    '--hash', action='store', help="Hash algorithm for siging",
    default="SHA512"
)
parser.add_argument(
    '--overwrite', "-o", action='store_true',
    help="overwrite private key"
)
parser.add_argument(
    '--cert', action="store", default=argparse.SUPPRESS,
    help='Certificate (used for smtp encryption)'
)
parser.add_argument(
    '--keysize', "-s", action='store', default=8192, type=int,
    help="Keysize for auto generated keys"
)
parser.add_argument(
    '--address', "-a", action='store', nargs="+",
    default="127.0.0.1"
)

parser.add_argument(
    '--verbose', "-v", action='count', default=0,
    help='Verbosity'
)


def main(argv):
    argv = parser.parse_args(argv)
    argv.cert = getattr(
        argv, "cert", "%s.cert" % argv.key.rsplit(".", 1)[0]
    )
    argv.hash = getattr(hashes, argv.hash)()
    cert = None
    if not argv.overwrite and os.path.exists(argv.key):
        with open(argv.key, "rb") as f:
            private_key = load_priv_key(f.read())
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=argv.keysize,
            backend=default_backend()
        )
        with open(argv.key, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
    subject = x509.Name(
        [
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME, "spkcspider"
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME, argv.address[0]
            ),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.utcnow())
        .not_valid_after(dt.utcnow() + td(days=365*20))
    )
    for address in argv.address[1:]:
        cert = cert.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(address)]),
            critical=False
        )

    cert = cert.sign(private_key, hashes.SHA512(), default_backend())
    del private_key

    with open(argv.cert, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


if __name__ == "__main__":
    main(sys.argv[1:])
