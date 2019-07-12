#!/usr/bin/env python3
import io
import sys
import os
import argparse
import getpass
import logging
import base64
import json
# import re

import requests
# from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import (
    load_pem_x509_certificate, load_der_x509_certificate
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_der_private_key,
    load_pem_public_key, load_der_public_key
)
from rdflib import Graph, XSD, Literal

from spkcspider.apps.spider.helpers import merge_get_url
from spkcspider.apps.spider.constants import static_token_matcher, spkcgraph
from spkcspider_messaging.constants import ReferenceType
from spkcspider_messaging.attestation import (
    AttestationChecker, AttestationResult
)


logger = logging.getLogger(__name__)

parser = argparse.ArgumentParser(
    description='Store or load message manually'
)
parser.add_argument(
    '--key', action='store', dest="key",
    default="key.priv", help='Private Key'
)
parser.add_argument(
    '--db', action='store', dest="attestation",
    default="attestation.sqlite3", help='DB for key attestation'
)
parser.add_argument(
    '--verbose', "-v", action='count', default=0,
    help='Verbosity'
)
parser.add_argument(
    'url',
    help='Postbox/Message'
)
subparsers = parser.add_subparsers(dest='action', required=True)
subparsers.add_parser("view")
subparsers.add_parser("peek")
subparsers.add_parser("check")
send_parser = subparsers.add_parser("send")
send_parser.add_argument(
    'dest', action="store", help='Destination url'
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
                )
            except ValueError:
                try:
                    return load_der_public_key(
                        key, defbackend
                    )
                except ValueError:
                    raise


def replace_action(url, action):
    url = url.split("?", 1)
    "?".join(
        "/".join(
            url.rstrip("/").rsplit("/", 1)[0], action
        ),
        url[1]
    )


def action_send(argv, access, pkey, pkey_hash, s, response):
    url = merge_get_url(argv.url, raw="true")
    g = Graph()
    g.parse(data=response.content, format="turtle")
    if (
        None, spkcgraph["create:name"], Literal(
            "MessageContent", datatype=XSD.string
        )
    ) not in g:
        parser.exit(1, "Source does not support action\n")
    response_dest = s.get(
        merge_get_url(argv.dest, raw="embed")
    )
    if not response_dest.ok:
        logging.info("Dest returned error: %s", response_dest.text)
        parser.exit(1, "url invalid\n")
    g_dest = Graph()
    g_dest.parse(data=response.content, format="turtle")
    dest_create = g_dest.value(
        predicate=spkcgraph["spkc:feature:name"],
        object=Literal(
            "webrefpush", datatype=XSD.string
        )
    )
    dest_info = s.get(dest_create).json
    url_create = replace_action(url, "add/MessageContent/")
    response = s.get(url_create)
    if not response.ok:
        logging.error("Creation failed: %s", response.text)
        parser.exit(1, "Creation failed: %s" % response.text)
    g = Graph()
    g.parse(data=response.content, format="html")
    if (
        None, spkcgraph["spkc:csrftoken"], None
    ) not in g_dest:
        logging.error("failure: no csrftoken: %s", response.text)
        parser.exit(1, "failure: no csrftoken\n")
    blob = sys.stdin.read()
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(20)
    src = {}
    src_key_list = {}
    dest_key_list = {}
    defbackend = default_backend()

    for i in g.query(
        """
            SELECT DISTINCT ?key_base ?key_name ?key_value
            WHERE {
                ?base spkc:name ?keys_name .
                ?base spkc:value ?key_base .
                ?key_base spkc:properties ?key_base_prop .
                ?key_base_prop spkc:name ?key_name .
                ?key_base_prop spkc:value ?key_value .
            }
        """,
        initNs={"spkc": spkcgraph},
        initBindings={
            "keys_name": Literal(
                "signatures", datatype=XSD.string
            )
        }
    ):
        src.setdefault(str(i.key_base), {})
        src[str(i.postbox_value)][str(i.key_name)] = i.key_value

    src_hash = getattr(hashes, next(iter(src))["hash_algorithm"].upper())()
    for k in src.values():
        partner_key = load_public_key(k["key"])

        enc = partner_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=src_hash),
                algorithm=src_hash,
                label=None
            )
        )
        partner_pem_public = partner_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        digest = hashes.Hash(src_hash, backend=default_backend())
        digest.update(partner_pem_public)
        partner_keyhash = digest.finalize().hex()
        # encrypt decryption key
        src_key_list[partner_keyhash] = base64.urlsafe_b64encode(enc)

    dest_hash = getattr(hashes, dest_info["hash_algorithm"])()
    updater = hashes.Hash(dest_hash, backend=defbackend)
    for mh in sorted(dest_info["keys"].keys()):
        updater.update(mh.encode("ascii", "ignore"))

    dest_activator_value = updater.finalize()
    errored = []

    for h, val in dest_info["keys"].items():
        dest_key = load_public_key(val["key"])
        hashalgo, signature = val["signature"].split("=", 1)
        hashalgo = getattr(hashes, hashalgo.upper())()
        try:
            dest_key.verify(
                base64.urlsafe_b64decode(signature),
                dest_activator_value,
                padding.PSS(
                    mgf=padding.MGF1(hashalgo),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashalgo
            )
        except InvalidSignature:
            errored.append(h)
            continue
        enc = dest_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=argv.hash),
                algorithm=argv.hash,
                label=None
            )
        )
        # encrypt decryption key
        dest_key_list[h] = base64.urlsafe_b64encode(enc)
    if errored:
        parser.exit(1, "Key validation failed\n")
    ctx = AESGCM(aes_key)
    blob = ctx.encrypt(
        nonce, b"Type: message\n\n%b" % (
            blob
        )
    )
    # create message object
    response = s.post(
        url_create, body={
            "own_hash": pkey_hash,
            "key_list": src_key_list,
            "encrypted_content": io.BytesIO(
                b"%b\0%b" % (nonce, blob)
            )
        }
    )
    response_dest = s.post(
        dest_create, body={
            "url": response.url,
            "rtype": ReferenceType.message,
            "key_list": dest_key_list
        }
    )


def action_view(argv, access, pkey, pkey_hash, s, response):
    if access == "ref":
        key_list = json.loads(response.headers["X-KEYLIST"])
        key = key_list.get("keyhash", None)
        if not key:
            parser.exit(0, "message not for me\n")
        decrypted_key = pkey.decrypt(
            key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=argv.hash),
                algorithm=argv.hash,
                label=None
            )
        )
        ctx = AESGCM(decrypted_key)
        nonce, content = response.content.split(b"\0", 1)
        blob = ctx.decrypt(nonce, content)
        headers, content = blob.split(b"\n\n", 1)
        print(content)
    else:
        g = Graph()
        g.parse(data=response.content, format="turtle")
        q = list(g.query(
            """
                SELECT DISTINCT ?base ?name ?value
                WHERE {
                    ?a spkc:name ?message_list .
                    ?a spkc:value ?base .
                    ?base spkc:name ?name .
                    ?base spkc:value ?value .
                }
            """,
            initNs={"spkc": spkcgraph},
            initBindings={
                "message_list": Literal(
                    "message_list", datatype=XSD.string
                )
            }
        ))
        if len(q) == 0:
            parser.exit(1, "postbox not found\n")
        q2 = {}
        for i in q:
            q2.setdefault(str(i.base), {})
            q2[str(i.base)][str(i.name)] = i.value
        print("Messages:")
        for i in q2:
            print(i["id"], i["sender"])
        # view


def action_check(argv, access, pkey, pkey_hash, s, response, verb=True):
    src = {}

    g = Graph()
    g.parse(data=response.content, format="turtle")

    for i in g.query(
        """
            SELECT
            ?postbox_value ?postbox_value ?key_name ?key_value
            WHERE {
                ?base spkc:name ?postbox_name .
                ?base spkc:value ?postbox_value .
                ?postbox_value spkc:properties ?key_base_prop .
                ?key_base_prop spkc:name ?key_name .
                ?key_base_prop spkc:value ?key_value .
            }
        """,
        initNs={"spkc": spkcgraph},
        initBindings={
            "postbox_name": Literal(
                "signatures", datatype=XSD.string
            )
        }
    ):
        src.setdefault(str(i.postbox_value), {})
        src[str(i.postbox_value)][str(i.key_name)] = i.key_value

    src_hash = getattr(
        hashes, next(iter(src.values()))["hash_algorithm"].upper()
    )()
    src_activator_value, errored = argv.attestation.check_signatures(
        map(
            lambda x: (x["key"], x["signature"]),
            src.values()
        ), algo=src_hash
    )
    tmp = list(g.query(
        """
            SELECT DISTINCT ?name ?value
            WHERE {
                ?base spkc:name ?name .
                ?base spkc:value ?value .
            }
        """,
        initNs={"spkc": spkcgraph},
        initBindings={
            "name": Literal(
                "attestation", datatype=XSD.string
            ),

        }
    ))
    if base64.urlsafe_b64decode(tmp[0].value) != src_activator_value:
        return "activator doesn't match shown activator"
    if errored:
        return ", ".join(errored)
    return True


def main(argv):
    argv = parser.parse_args(argv)
    argv.attestation = AttestationChecker(argv.attestation)
    if not os.path.exists(argv.key):
        parser.exit(1, "key does not exist\n")
    match = static_token_matcher.match(argv.url)
    if not match:
        parser.exit(1, "invalid url\n")
    if argv.verbose >= 2:
        logger.setLevel(logging.DEBUG)
    elif argv.verbose >= 1:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)
    access = match.groupdict()["access"]
    if (
        argv.action == "check" and
        access not in {"view", "list"}
    ):
        parser.exit(1, "url doesn't match action\n")
    if (
        argv.action in {"view", "peek"} and
        access not in {"view", "ref", "list"}
    ):
        parser.exit(1, "url doesn't match action\n")
    if (
        argv.action == "fix" and
        access != "update"
    ):
        parser.exit(1, "url doesn't match action\n")
    if argv.action == "send":
        match2 = static_token_matcher.match(argv.dest)
        if not match2:
            parser.exit(1, "invalid url\n")
        access2 = match2.groupdict()["access"]
        if (
            access == "list" or
            access2 not in {"list", "view"}
        ):
            parser.exit(1, "url doesn't match action\n")

    with open(argv.key, "rb") as f:
        pkey = load_priv_key(f.read())[0]

        if not pkey:
            parser.exit(1, "invalid key: %s\n" % argv.key)
        pem_public = pkey.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    with requests.Session() as s:
        if access == "list":
            own_url = merge_get_url(
                argv.url, raw="embed", info="_type=PostBox"
            )
        else:
            own_url = merge_get_url(argv.url, raw="embed")
        response = s.get(own_url)
        if not response.ok:
            logging.info("Url returned error: %s\n", response.text)
            parser.exit(1, "url invalid\n")

        g = Graph()
        g.parse(data=response.content, format="turtle")
        src = {}

        for i in g.query(
            """
                SELECT
                ?postbox_value ?postbox_value ?key_name ?key_value
                WHERE {
                    ?base spkc:name ?postbox_name .
                    ?base spkc:value ?postbox_value .
                    ?postbox_value spkc:properties ?key_base_prop .
                    ?key_base_prop spkc:name ?key_name .
                    ?key_base_prop spkc:value ?key_value .
                }
            """,
            initNs={"spkc": spkcgraph},
            initBindings={
                "postbox_name": Literal(
                    "signatures", datatype=XSD.string
                )
            }
        ):
            src.setdefault(str(i.postbox_value), {})
            src[str(i.postbox_value)][str(i.key_name)] = i.key_value

        # algorithm for hashing
        argv.src_hash_algo = getattr(
            hashes, next(iter(src.values()))["hash_algorithm"].upper()
        )()

        digest = hashes.Hash(argv.src_hash_algo, backend=default_backend())
        digest.update(pem_public)
        pkey_hash = digest.finalize().hex()
        argv.attestation.add(own_url.split("?", 1)[0], [pkey_hash])
        if argv.action != "check":
            result_own = argv.attestation.check(
                own_url.split("?", 1)[0],
                map(
                    lambda x: (x["key"], x["signature"]),
                    src.values()
                ),
                algo=argv.src_hash_algo
            )
            if result_own != AttestationResult.success:
                logging.critical(
                    "Home base url contains invalid keys, hacked?"
                )
                parser.exit(1, "invalid keys\n")
        # check own domain

        if argv.action == "view":
            response = s.post(
                merge_get_url(argv.url, raw="embed"),
                body={
                    "keyhash": pkey_hash
                }
            )

        if argv.action == "send":
            return action_send(argv, access, pkey, pkey_hash, s, response)
        elif argv.action in {"view", "peek"}:
            return action_view(argv, access, pkey, pkey_hash, s, response)
        elif argv.action == "check":
            ret = action_check(argv, access, pkey, pkey_hash, s, response)
            if ret is not True:
                parser.exit(2, "check failed: %s\n" % ret)


if __name__ == "__main__":
    main(sys.argv[1:])
