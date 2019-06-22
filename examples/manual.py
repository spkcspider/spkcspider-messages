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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_der_private_key,
    load_pem_public_key, load_der_public_key
)
from rdflib import Graph, XSD, Literal

from spkcspider.apps.spider.helpers import merge_get_url
from spkcspider.apps.spider.constants import static_token_matcher, spkcgraph


parser = argparse.ArgumentParser(
    description='Store or load message manually'
)
parser.add_argument(
    '--hash', action='store', help="Hash algorithm", default="SHA512"
)
parser.add_argument(
    '--key', action='store', dest="key",
    default="key.priv", help='Private Key'
)
parser.add_argument(
    '--cert', action="store", default=argparse.SUPPRESS,
    help='Certificate (used for smtp encryption)'
)
parser.add_argument(
    '--verbose', "-v", action='count',
    help='Verbosity'
)
parser.add_argument(
    'url',
    help='Postbox/Message'
)
subparsers = parser.add_subparsers(dest='action')
subparsers.add_parser("view")
subparsers.add_parser("peek")
subparsers.add_parser("fix")
send_parser = subparsers.add_parser("send")
send_parser.add_argument(
    'dest', action="store", required=True,
    help='Destination url'
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


def replace_action(url, action):
    url = url.split("?", 1)
    "?".join(
        "/".join(
            url.rstrip("/").rsplit("/", 1)[0], action
        ),
        url[1]
    )


def main(argv):
    argv = parser.parse_args(argv)
    if not os.path.exists(argv.key):
        argv.exit(1, "key does not exist")
    match = static_token_matcher.match(argv.url)
    if not match:
        argv.exit(1, "invalid url")
    if argv.verbose >= 2:
        logging.setLevel(logging.DEBUG)
    elif argv.verbose >= 1:
        logging.setLevel(logging.INFO)
    else:
        logging.setLevel(logging.WARNING)
    access = match.groupdict()["access"]
    if (
        argv.action in {"view", "peek"} and
        access not in {"view", "ref", "list"}
    ):
        argv.exit(1, "url doesn't match action")
    if (
        argv.action == "fix" and
        access != "update"
    ):
        argv.exit(1, "url doesn't match action")
    if argv.action == "send":
        match2 = static_token_matcher.match(argv.dest)
        if not match2:
            argv.exit(1, "invalid url")
        access2 = match2.groupdict()["access"]
        if (
            access == "list" or
            access2 not in {"list", "view"}
        ):
            argv.exit(1, "url doesn't match action")

    with open(argv.key, "rb") as f:
        pkey = load_priv_key(f.read())[0]

        if not pkey:
            argv.exit(1, "invalid key: %s" % argv.key)
        pem_public = pkey.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        digest = hashes.Hash(argv.hash, backend=default_backend())
        digest.update(pem_public)
        keyhash = digest.finalize().hex()

    with requests.Session() as s:
        if access == "list":
            response = s.get(
                merge_get_url(
                    argv.url, raw="embed", info="_type=PostBox"
                ),
                body={
                    "keyhash": keyhash
                }
            )
        elif argv.action == "view":
            response = s.post(
                merge_get_url(argv.url, raw="embed"),
                body={
                    "keyhash": keyhash
                }
            )
        else:
            response = s.get(
                merge_get_url(argv.url, raw="embed")
            )
        if not response.ok:
            logging.info("Url returned error: %s", response.text)
            argv.exit(1, "url invalid")

        if argv.action == "send":
            url = merge_get_url(argv.url, raw="true")
            g = Graph()
            g.parse(data=response.content, format="turtle")
            if (
                None, spkcgraph["create:name"], Literal(
                    "MessageContent", datatype=XSD.string
                )
            ) not in g:
                argv.exit(1, "Source does not support action")
            response_dest = s.get(
                merge_get_url(argv.dest, raw="embed")
            )
            if not response_dest.ok:
                logging.info("Dest returned error: %s", response_dest.text)
                argv.exit(1, "url invalid")
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
                argv.exit(1, "Creation failed: %s" % response.text)
            g = Graph()
            g.parse(data=response.content, format="html")
            if (
                None, spkcgraph["spkc:csrftoken"], None
            ) not in g_dest:
                logging.error("failure: no csrftoken: %s", response.text)
                argv.exit(1, "failure: no csrftoken")
            blob = sys.stdin.read()
            aes_key = AESGCM.generate_key(bit_length=256)
            nonce = os.urandom(20)
            src_key_list = {}
            dest_key_list = {}
            defbackend = default_backend()
            for key in g.query(
                """
                    SELECT DISTINCT ?key_value
                    WHERE {
                        ?base spkc:name ?keys_name .
                        ?base spkc:value ?keybase .
                        ?key_base spkc:properties ?key_base_prop .
                        ?key_base_prop spkc:name ?key_name .
                        ?key_base_prop spkc:value ?key_value .
                    }
                """,
                initNs={"spkc": spkcgraph},
                initBindings={
                    "key_name": Literal(
                        "key", datatype=XSD.string
                    ),
                    "keys_name": Literal(
                        "keys", datatype=XSD.string
                    )
                }
            ):
                try:
                    partner_key = load_pem_public_key(key, None, defbackend)
                except ValueError:
                    try:
                        partner_key = load_der_public_key(
                            key, None, defbackend
                        )
                    except ValueError:
                        raise
                enc = pkey.encrypt(
                    aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=argv.hash),
                        algorithm=argv.hash,
                        label=None
                    )
                )
                partner_pem_public = partner_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                digest = hashes.Hash(argv.hash, backend=default_backend())
                digest.update(partner_pem_public)
                partner_keyhash = digest.finalize().hex()
                src_key_list[partner_keyhash] = base64.urlsafe_b64encode(enc)

            for i in dest_info["keys"].items():
                try:
                    pkey = load_pem_public_key(i[1], None, defbackend)
                except ValueError:
                    try:
                        pkey = load_der_public_key(i[1], None, defbackend)
                    except ValueError:
                        raise
                enc = pkey.encrypt(
                    aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=argv.hash),
                        algorithm=argv.hash,
                        label=None
                    )
                )
                dest_key_list[i[0]] = base64.urlsafe_b64encode(enc)
            ctx = AESGCM(aes_key)
            blob = ctx.encrypt(
                nonce, b"Type: message\n\n%b" % (
                    blob
                )
            )
            # create message object
            response = s.post(
                url_create, body={
                    "own_hash": keyhash,
                    "key_list": src_key_list,
                    "encrypted_content": io.BytesIO(
                        b"%b\0%b" % (nonce, blob)
                    )
                }
            )
            response_dest = s.post(
                dest_create, body={
                    "": None,
                    "key_list": dest_key_list
                }
            )

        elif argv.action in {"view", "peek"}:
            if access == "ref":
                key_list = json.loads(response.headers["X-KEYLIST"])
                key = key_list.get("keyhash", None)
                if not key:
                    argv.exit(0, "message not for me")
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
                q = list(g.query(
                    """
                        SELECT DISTINCT ?base, ?name, ?value
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
                    argv.exit(1, "postbox not found")
                q2 = {}
                for i in q:
                    q2.setdefault(i.base, {})
                    q2[i.base][i.name] = i.value
                print("Messages:")
                for i in q2:
                    print(i["id"], i["sender"])
                # view
        elif argv.action == "fix":
            pass


if __name__ == "__main__":
    main(sys.argv)
