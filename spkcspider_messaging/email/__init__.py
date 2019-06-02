import os
import asyncio
import logging
from datetime import datetime as dt, timedelta as td

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from OpenSSL import crypto

from twisted.internet import asyncioreactor, ssl

from .cmd import parser
from .core import load_priv_key
from .smtp import SMTPFactory
from .pop3 import POP3Factory

logger = logging.getLogger(__name__)


def main(argv):
    argv = parser.parse_args(argv)
    argv.cert = getattr(
        argv, "cert", "%s.cert" % argv.keys[0].rsplit(".", 1)[0]
    )
    argv.hash = getattr(hashes, argv.hash)()
    cert = None
    if not os.path.exists(argv.keys[0]) and not argv.no_gen:
        pkey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=argv.keysize,
            backend=default_backend()
        )
        with open(argv.keys[0], "wb") as f:
            f.write(
                pkey.private_bytes(
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
                    NameOID.COMMON_NAME, argv.address
                ),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(pkey.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt.utcnow())
            .not_valid_after(dt.utcnow() + td(days=365*20))
        )
        # cert = cert.add_extension(
        #    x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        #    critical=False
        # )

        cert = cert.sign(pkey, hashes.SHA512(), default_backend())
        del pkey

        pkey_file = argv.keys[0].rsplit(".", 1)[0]
        with open(pkey_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    if not all(map(os.path.exists, argv.keys)):
        argv.exit(1, "invalid keys")
    keylist = {}
    pw = None
    for num, key_path in enumerate(argv.keys):
        data = None
        pkey = None
        with open(key_path, "rb") as f:
            if num == 0:
                pkey, pw = load_priv_key(f.read())
            else:
                pkey = load_priv_key(f.read())[0]

            if not pkey:
                argv.exit(1, "invalid key: %s" % key_path)
            pem_public = pkey.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            digest = hashes.Hash(argv.hash, backend=default_backend())
            digest.update(pem_public)
            keylist[digest.finalize().hex()] = pkey
        del data
        del pkey
    ctx = None
    if os.path.exists(argv.cert):
        pubdata = None
        with open(argv.cert, "rb") as f:
            pubdata = f.read()
        privdata = None
        with open(argv.keys[0], "rb") as f:
            privdata = f.read()

        ctx = ssl.PrivateCertificate.load(
            pubdata, privdata, crypto.FILETYPE_PEM
        )

    loop = asyncio.new_event_loop()
    reactor = asyncioreactor.AsyncioSelectorReactor(loop)
    smtp_factory = SMTPFactory()
    smtp_factory.domain = argv.address
    smtp_factory.encryption_required = not argv.unencrypted
    if ctx:
        smtp_factory.cert_options = ssl.optionsForClientTLS(
            argv.address, ctx
        )
    reactor.listenTCP(argv.smtp_port, smtp_factory, interface=argv.address)

    pop3_factory = POP3Factory()
    pop3_factory.domain = argv.address
    pop3_factory.encryption_required = not argv.unencrypted
    if ctx:
        pop3_factory.options = ssl.optionsForClientTLS(
            argv.address, ctx
        )
    reactor.listenTCP(argv.pop3_port, pop3_factory, interface=argv.address)
    logger.info("spkcspider pipeline started")
    loop.run_forever()
