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

from spider_messaging.constants import ReferenceType, AttestationResult
from spider_messaging.attestation import (
    AttestationChecker
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
view_parser.add_argument(
    'message_id', help='View message with id', nargs="?"
)
peek_parser = subparsers.add_parser("peek")
peek_parser.add_argument(
    '--file', help='Use file instead stdout', type=argparse.FileType('wb'),
    nargs="?", default=sys.stdout.buffer
)
peek_parser.add_argument(
    'message_id', help='View message with id', nargs="?"
)
check_parser = subparsers.add_parser("check")
check_parser.add_argument(
    '--fix', help="Fix problems",
    action="store_true"
)
send_parser = subparsers.add_parser("send")
send_parser.add_argument(
    '--file', help='Use file instead stdin', type=argparse.FileType('rb'),
    nargs="?", default=sys.stdin.buffer
)
send_parser.add_argument(
    '--stealth', help="Don't save sender or source key hashes",
    action="store_true"
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


def analyze_src(graph):
    component_uriref = graph.value(
        predicate=spkcgraph["create:name"], object=Literal(
            "MessageContent", datatype=XSD.string
        )
    )
    # src_postbox_url = merge_get_url(src_postbox_url, raw="true")
    options = {}
    for i in graph.query(
        """
            SELECT ?key ?value
            WHERE {
                ?postbox spkc:type ?postbox_type.
                ?postbox spkc:properties ?base .
                ?base spkc:name ?key ;
                      spkc:value ?value .
            }
        """,
        initNs={"spkc": spkcgraph},
        initBindings={
            "postbox_type": Literal(
                "PostBox", datatype=XSD.string
            )
        }
    ):
        if isinstance(i.value, Literal):
            options[str(i.key)] = i.value.value

    return component_uriref, options


def analyse_dest(graph):
    postbox_uriref = graph.value(
        predicate=spkcgraph["ability:name"],
        object=Literal("push_webref", datatype=XSD.string)
    )
    if not postbox_uriref:
        return None, None, {}, None
        # parser.exit(1, "dest does not support push_webref ability\n")
    webref_url = replace_action(str(postbox_uriref), "push_webref/")
    # response_dest = session.get(
    #     merge_get_url(webref_url, raw="embed")
    # )
    # if not response_dest.ok:
    #    logger.info("Dest returned error: %s", response_dest.text)
    #     parser.exit(1, "url invalid\n")
    # g_dest = Graph()
    # g_dest.parse(data=response_dest.content, format="turtle")

    domain_keys = {}

    for i in graph.query(
        """
            SELECT
            ?postbox_value ?value ?key_name ?key_value
            WHERE {
                ?postbox spkc:properties ?base_prop .
                ?base_prop spkc:name ?postbox_name ;
                           spkc:value ?postbox_value .
                ?postbox_value spkc:properties ?key_base_prop .
                ?key_base_prop spkc:name ?key_name ;
                               spkc:value ?key_value .
            }
        """,
        initNs={"spkc": spkcgraph},
        initBindings={
            "postbox": postbox_uriref,
            "postbox_name": Literal(
                "signatures", datatype=XSD.string
            )
        }
    ):
        domain_keys.setdefault(str(i.postbox_value), {})
        domain_keys[str(i.postbox_value)][str(i.key_name)] = i.key_value.value
    hash_algo = getattr(
        hashes, next(iter(domain_keys.values()))["hash_algorithm"].upper()
    )()
    return postbox_uriref, webref_url, domain_keys, hash_algo


def action_send(argv, priv_key, pub_key_hash, session, response, src_keys):
    g_src = Graph()
    g_src.parse(data=response.content, format="turtle")
    component_uriref, src_options = analyze_src(g_src)
    if not component_uriref:
        parser.exit(1, "Source cannot create messages, logged in?")

    dest_url = merge_get_url(argv.dest, raw="embed", info="_type=PostBox")
    response_dest = session.get(dest_url)
    if not response_dest.ok:
        logger.info("Dest returned error: %s", response_dest.text)
        parser.exit(1, "retrieval failed, invalid url?\n")
    dest = {}
    g_dest = Graph()
    g_dest.parse(data=response_dest.content, format="turtle")
    dest_postbox_url, webref_url, dest, dest_hash = analyse_dest(g_dest)

    bdomain = dest_postbox_url.split("?", 1)[0]
    result_dest, _, dest_keys = argv.attestation.check(
        bdomain,
        map(
            lambda x: (x["key"], x["signature"]),
            dest.values()
        ),
        algo=dest_hash
    )
    if result_dest == AttestationResult.domain_unknown:
        logger.info("add domain: %s", bdomain)
        argv.attestation.add(
            bdomain,
            map(
                lambda x: (x["key"], x["signature"]),
                dest.values()
            ),
            algo=dest_hash
        )
    elif result_dest == AttestationResult.error:
        logger.critical("Dest base url contains invalid keys.")
        parser.exit(1, "dest contains invalid keys\n")

    blob = argv.file.read()
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(20)
    src_key_list = {}
    dest_key_list = {}
    if argv.stealth:
        pass
    elif src_options["shared"]:
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
    else:
        enc = priv_key.public_key().encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=argv.src_hash_algo),
                algorithm=argv.src_hash_algo, label=None
            )
        )
        # encrypt decryption key
        src_key_list[pub_key_hash] = \
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
    headers = b"SPKC-Type: message\n"
    blob = ctx.encrypt(
        nonce, b"%b\n%b" % (
            headers,
            blob
        ), None
    )
    # remove raw as we parse html
    message_create_url = merge_get_url(
        replace_action(str(component_uriref), "add/MessageContent/"), raw=None
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
            "own_hash": pub_key_hash,
            "key_list": json.dumps(src_key_list),
            "amount_tokens": 1
        }, headers={
            "X-CSRFToken": csrftoken,
            "X-TOKEN": argv.token  # only for src
        },
        files={
            "encrypted_content": io.BytesIO(
                b"%b\0%b" % (nonce, blob)
            )
        }
    )
    if not response.ok or message_create_url == response.url:
        logger.error("Message creation failed: %s", response.text)
        parser.exit(1, "Message creation failed: %s" % response.text)
    g = Graph()
    g.parse(data=response.content, format="html")
    q = list(g.query(
        """
            SELECT DISTINCT ?value
            WHERE {
                ?property spkc:name ?name .
                ?property spkc:value ?value .
            }
        """,
        initNs={"spkc": spkcgraph},
        initBindings={
            "name": Literal(
                "fetch_url", datatype=XSD.string
            )
        }
    ))

    q2 = list(g.query(
        """
            SELECT DISTINCT ?value
            WHERE {
                ?property spkc:name ?name .
                ?property spkc:value ?value .
            }
        """,
        initNs={"spkc": spkcgraph},
        initBindings={
            "name": Literal(
                "tokens", datatype=XSD.string
            )
        }
    ))

    if not q or not q2:
        logger.error("Message creation failed: %s", response.text)
        parser.exit(1, "Message creation failed: %s" % response.text)
    # extract url
    response_dest = session.post(
        webref_url, data={
            "url": merge_get_url(q[0].value, token=str(q2[0])),
            "rtype": ReferenceType.message,
            "key_list": json.dumps(dest_key_list)
        }
    )
    response_dest.raise_for_status()


def action_view(argv, priv_key, pub_key_hash, session, response):
    g_message = Graph()
    g_message.parse(data=response.content, format="turtle")
    if argv.message_id is not None:
        postbox_url = g_message.value(
            predicate=spkcgraph["type"],
            object=Literal("PostBox", datatype=XSD.string)
        )
        getref_url = merge_get_url(
            replace_action(
                postbox_url, "get_webref/"
            ), reference=argv.message_id
        )
        if argv.action == "peek":
            response = session.get(
                getref_url, headers={
                    "X-TOKEN": argv.token
                }
            )
        else:
            response = session.post(
                getref_url, headers={
                    "X-TOKEN": argv.token
                }, data={
                    "keyhash": pub_key_hash
                }
            )
        if not response.ok:
            logger.info("Message retrievel failed: %s", response.text)
            parser.exit(0, "message not found\n")
        # own_key_hash = getattr(
        #     hashes, response.headers["X-KEYHASH-ALGO"].upper()
        # )()
        key_list = json.loads(response.headers["X-KEYLIST"])
        key = key_list.get(pub_key_hash, None)
        if not key:
            parser.exit(0, "message not for me\n")
        decrypted_key = priv_key.decrypt(
            base64.urlsafe_b64decode(key),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=argv.src_hash_algo),
                algorithm=argv.src_hash_algo,
                label=None
            )
        )
        ctx = AESGCM(decrypted_key)
        nonce, content = response.content.split(b"\0", 1)
        blob = ctx.decrypt(nonce, content, None)
        headers, content = blob.split(b"\n\n", 1)
        argv.file.write(content)
    else:
        queried = {}
        for i in g_message.query(
            """
                SELECT DISTINCT ?base ?message_name ?message_value
                WHERE {
                    ?property spkc:name ?search_name .
                    ?property spkc:value ?base .
                    ?base spkc:properties ?message_base_prop .
                    ?message_base_prop spkc:name ?message_name .
                    ?message_base_prop spkc:value ?message_value .
                }
            """,
            initNs={"spkc": spkcgraph},
            initBindings={
                "search_name": Literal(
                    "webreferences", datatype=XSD.string
                )
            }
        ):
            queried.setdefault(str(i.base), {})
            queried[str(i.base)][str(i.message_name)] = i.message_value
        if len(queried) == 0 and not g_message.value(
            predicate=spkcgraph["name"],
            object=Literal(
                "webreferences", datatype=XSD.string
            )
        ):
            parser.exit(1, "message references not found; logged in?\n")
        print("Messages:")
        for i in sorted(queried.values(), key=lambda x: x["id"]):
            print(i["id"], i["sender"])


def action_check(argv, priv_key, pub_key_hash, session, response):
    src = {}

    g = Graph()
    g.parse(data=response.content, format="turtle")
    postbox = None

    for i in g.query(
        """
            SELECT
            ?postbox ?key_base_prop ?key_name ?key_value
            WHERE {
                ?postbox spkc:properties ?postbox_prop .
                ?postbox_prop spkc:name ?postbox_prop_name .
                ?postbox_prop spkc:value ?key_base .
                ?key_base spkc:properties ?key_base_prop .
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
        postbox = i.postbox
        src.setdefault(str(i.key_base), {})
        src[str(i.key_base)][str(i.key_name)] = i.key_value

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
        if argv.fix:
            pub_key_hash_bin = bytes.fromhex(pub_key_hash)
            can_fix = list(filter(lambda x: x[0] == pub_key_hash_bin, errored))
            csrftoken = list(g.objects(predicate=spkcgraph["csrftoken"]))[0]
            if not can_fix or not postbox:
                return ", ".join(map(lambda x: x[0].hex(), errored))

            postbox_update = replace_action(
                postbox, "update/"
            )
            finished_signatures = []
            for key in can_fix:
                signature = key[1].sign(
                    base64.urlsafe_b64decode(src_activator_value),
                    padding.PSS(
                        mgf=padding.MGF1(argv.hash),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    argv.hash
                )
                finished_signatures.append(
                    {
                        "hash": key[0].hex(),
                        "signature": "{}={}".format(
                            src_hash,
                            base64.urlsafe_b64encode(signature).decode("ascii")
                        )
                    }
                )
            # update
            response = session.post(
                postbox_update, data={
                    "signatures": finished_signatures
                }, headers={
                    "X-CSRFToken": csrftoken,
                    "X-TOKEN": argv.token
                }
            )
            if not response.ok:
                raise
            if len(can_fix) == len(errored):
                return True
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
        access not in {"view", "list"}
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
        priv_key = load_priv_key(f.read())[0]

        if not priv_key:
            parser.exit(1, "invalid key: %s\n" % argv.key)
        pem_public = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    with requests.Session() as s:
        if access == "get_ref":
            own_url = merge_get_url(
                replace_action(
                    argv.url, "view/"
                ), raw="embed"
            )
        elif access == "list":
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
        pub_key_hash = digest.finalize().hex()
        argv.attestation.add(
            own_url.split("?", 1)[0], [pub_key_hash], argv.src_hash_algo
        )
        src_keys = None
        if argv.action != "check":
            result_own, errored, src_keys = argv.attestation.check(
                own_url.split("?", 1)[0],
                map(
                    lambda x: (x["key"], x["signature"]),
                    src.values()
                ),
                algo=argv.src_hash_algo, auto_add=True
            )
            if result_own == AttestationResult.domain_unknown:
                logger.critical(
                    "home url unknown, should not happen"
                )
                parser.exit(1, "invalid home url\n")
            elif result_own != AttestationResult.success:
                logger.critical(
                    "Home base url contains invalid keys, hacked?"
                )
                parser.exit(1, "invalid keys\n")
        # check own domain

        if argv.action == "send":
            return action_send(
                argv, priv_key, pub_key_hash, s, response, src_keys
            )
        elif argv.action in {"view", "peek"}:
            return action_view(argv, priv_key, pub_key_hash, s, response)
        elif argv.action == "check":
            ret = action_check(argv, priv_key, pub_key_hash, s, response)
            if ret is not True:
                parser.exit(2, "check failed: %s\n" % ret)
            print("check successful")


if __name__ == "__main__":
    main(sys.argv[1:])
