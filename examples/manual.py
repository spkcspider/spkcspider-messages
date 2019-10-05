#!/usr/bin/env python3
import io
import sys
import os
import argparse
import logging
import base64
import json
# import re

import requests
# from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from rdflib import Graph, XSD, Literal

from spkcspider.utils.urls import merge_get_url
from spkcspider.constants import static_token_matcher, spkcgraph

from spider_messaging.constants import ReferenceType
from spider_messaging.attestation import (
    AttestationChecker, AttestationResult
)
from spider_messaging.keys import load_priv_key


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
    '--token', default="",
    help='Optional login token, requires elsewise auth token for postbox'
)
parser.add_argument(
    'url',
    help='Postbox/Message'
)
subparsers = parser.add_subparsers(dest='action', required=True)
view_parser = subparsers.add_parser("view")
view_parser.add_argument(
    '--file', help='Use file instead stdout', type=argparse.FileType('wb'),
    nargs="?", default=sys.stdout.buffer
)
peek_parser = subparsers.add_parser("peek")
peek_parser.add_argument(
    '--file', help='Use file instead stdout', type=argparse.FileType('wb'),
    nargs="?", default=sys.stdout.buffer
)
subparsers.add_parser("check")
send_parser = subparsers.add_parser("send")
send_parser.add_argument(
    '--file', help='Use file instead stdin', type=argparse.FileType('rb'),
    nargs="?", default=sys.stdin.buffer
)
send_parser.add_argument(
    'dest', action="store", help='Destination url'
)


def replace_action(url, action):
    url = url.split("?", 1)
    # urljoin does not join correctly, removes token because of no ending /
    return "?".join(
        [
            "/".join((
                url[0].rstrip("/").rsplit("/", 1)[0], action.lstrip("/")
            )),
            url[1] if len(url) >= 2 else ""
        ]
    )


def action_send(argv, pkey, pkey_hash, session, response, src_keys):
    g_src = Graph()
    g_src.parse(data=response.content, format="turtle")
    component_url = g_src.value(
        predicate=spkcgraph["create:name"], object=Literal(
            "MessageContent", datatype=XSD.string
        )
    )
    if not component_url:
        parser.exit(1, "Source does not support action, logged in?\n")
    component_url = merge_get_url(component_url, raw="true")

    dest_url = merge_get_url(argv.dest, raw="embed", info="_type=PostBox")
    response_dest = session.get(dest_url)
    if not response_dest.ok:
        logger.info("Dest returned error: %s", response_dest.text)
        parser.exit(1, "retrieval failed, invalid url?\n")
    dest = {}
    g_dest = Graph()
    g_dest.parse(data=response.content, format="turtle")

    webref_url = g_dest.value(
        predicate=spkcgraph["ability:name"],
        object=Literal("push_webref", datatype=XSD.string)
    )
    if not webref_url:
        parser.exit(1, "dest does not support push_webref ability\n")
    webref_url = replace_action(webref_url, "push_webref/")
    response_dest = session.get(
        merge_get_url(webref_url, raw="embed")
    )
    if not response_dest.ok:
        logger.info("Dest returned error: %s", response_dest.text)
        parser.exit(1, "url invalid\n")
    g_dest = Graph()
    g_dest.parse(data=response_dest.content, format="turtle")

    for i in g_src.query(
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
        dest.setdefault(str(i.postbox_value), {})
        dest[str(i.postbox_value)][str(i.key_name)] = i.key_value
    dest_hash = getattr(
        hashes, next(iter(dest.values()))["hash_algorithm"].upper()
    )()
    result_dest, errored, dest_keys = argv.attestation.check(
        response_dest.url.split("?", 1)[0],
        map(
            lambda x: (x["key"], x["signature"]),
            dest.values()
        ),
        algo=dest_hash
    )
    if result_dest != AttestationResult.success:
        logger.critical("Dest base url contains invalid keys.")
        parser.exit(1, "dest contains invalid keys\n")

    blob = argv.file.read()
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(20)
    src_key_list = {}
    dest_key_list = {}
    for k in src_keys:
        enc = k[1].encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=argv.src_hash_algo),
                algorithm=argv.src_hash_algo, label=None
            )
        )
        # encrypt decryption key
        src_key_list[k[0].hex()] = \
            base64.urlsafe_b64encode(enc).decode("ascii")

    for k in dest_keys:
        enc = k[1].encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=dest_hash),
                algorithm=dest_hash, label=None
            )
        )
        # encrypt decryption key
        dest_key_list[k[0].hex()] = \
            base64.urlsafe_b64encode(enc).decode("ascii")
    ctx = AESGCM(aes_key)
    blob = ctx.encrypt(
        nonce, b"Type: message\n\n%b" % (
            blob
        ), None
    )
    # remove raw as we parse html
    message_create_url = merge_get_url(
        replace_action(component_url, "add/MessageContent/"), raw=None
    )
    response = session.get(
        message_create_url, headers={
            "X-TOKEN": argv.token
        }
    )
    if not response.ok:
        logger.error("retrieval csrftoken failed: %s", response.text)
        parser.exit(1, "retrieval csrftoken failed: %s" % response.text)
    g = Graph()
    g.parse(data=response.content, format="html")
    csrftoken = list(g.objects(predicate=spkcgraph["csrftoken"]))[0]
    # create message object
    response = session.post(
        message_create_url, data={
            "own_hash": pkey_hash,
            "key_list": json.dumps(src_key_list),
            "encrypted_content": io.BytesIO(
                b"%b\0%b" % (nonce, blob)
            )
        }, headers={
            "X-CSRFToken": csrftoken,
            "X-TOKEN": argv.token  # only for src
        }
    )
    if not response.ok:
        logger.error("Message creation failed: %s", response.text)
        parser.exit(1, "Message creation failed: %s" % response.text)
    response_dest = session.post(
        webref_url, data={
            "url": response.url,
            "rtype": ReferenceType.message,
            "key_list": json.dumps(dest_key_list)
        }
    )
    response_dest.raise_for_status()


def action_view(argv, pkey, pkey_hash, session, response):
    if argv.access_type == "get_webref":
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
        argv.file.write(content)
        if argv.action == "view":
            response = session.post(
                merge_get_url(argv.url, raw="embed"),
                data={
                    "keyhash": pkey_hash
                }, headers={
                    "X-TOKEN": argv.token
                }
            )
    else:
        g = Graph()
        g.parse(data=response.content, format="turtle")
        q = list(g.query(
            """
                SELECT DISTINCT ?base ?name ?value
                WHERE {
                    ?property spkc:name ?message_list .
                    ?property spkc:value ?base .
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
        breakpoint()
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


def action_check(argv, pkey, pkey_hash, session, response, verb=True):
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
    )[:2]
    tmp = list(g.query(
        """
            SELECT DISTINCT ?value
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
    if base64.urlsafe_b64decode(tmp[0][0].value) != src_activator_value:
        return "activator doesn't match shown activator"
    if errored:
        return ", ".join(map(lambda x: x[0].hex(), errored))
    return True


def main(argv):
    argv = parser.parse_args(argv)
    argv.attestation = AttestationChecker(argv.attestation)
    if not os.path.exists(argv.key):
        parser.exit(1, "key does not exist\n")
    match = static_token_matcher.match(argv.url)
    if not match:
        parser.exit(1, "invalid url scheme\n")
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
        access not in {"view", "get_webref", "list"}
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
            parser.exit(1, "invalid url scheme\n")
        access2 = match2.groupdict()["access"]
        if (
            access not in {"list", "view", "push_webref"} or
            access2 not in {"list", "view", "push_webref"}
        ):
            parser.exit(1, "url doesn't match action\n")

    argv.access_type = access

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

        response = s.get(own_url, headers={
            "X-TOKEN": argv.token
        })
        if not response.ok:
            logger.info("Url returned error: %s\n", response.text)
            parser.exit(1, "retrieval failed, invalid url?\n")

        g = Graph()
        g.parse(data=response.content, format="turtle")
        src = {}

        for i in g.query(
            """
                SELECT
                ?postbox ?postbox_value ?postbox_value ?key_name ?key_value
                WHERE {
                    ?postbox spkc:properties ?property .
                    ?property spkc:name ?postbox_name .
                    ?property spkc:value ?postbox_value .
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
            argv.postbox_base = i.postbox
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
        src_keys = None
        if argv.action != "check":
            result_own, errored, src_keys = argv.attestation.check(
                own_url.split("?", 1)[0],
                map(
                    lambda x: (x["key"], x["signature"]),
                    src.values()
                ),
                algo=argv.src_hash_algo
            )
            if result_own != AttestationResult.success:
                logger.critical(
                    "Home base url contains invalid keys, hacked?"
                )
                parser.exit(1, "invalid keys\n")
        # check own domain

        if argv.action == "send":
            return action_send(
                argv, pkey, pkey_hash, s, response, src_keys
            )
        elif argv.action in {"view", "peek"}:
            return action_view(
                argv, pkey, pkey_hash, s, response
            )
        elif argv.action == "check":
            ret = action_check(argv, pkey, pkey_hash, s, response)
            if ret is not True:
                parser.exit(2, "check failed: %s\n" % ret)
            print("check successful")


if __name__ == "__main__":
    main(sys.argv[1:])
