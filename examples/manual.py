#!/usr/bin/env python3
import sys
import os
import argparse
import logging
import base64
import json
import io
from email import policy, parser as emailparser
# import re

import requests
# from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from rdflib import Graph, XSD, Literal

from spkcspider.utils.urls import merge_get_url
from spkcspider.constants import static_token_matcher, spkcgraph

from spider_messaging.constants import AttestationResult, MessageType
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
    'message_id', help='View message with id', nargs="?", type=int
)
peek_parser = subparsers.add_parser("peek")
peek_parser.add_argument(
    '--file', help='Use file instead stdout', type=argparse.FileType('wb'),
    nargs="?", default=sys.stdout.buffer
)
peek_parser.add_argument(
    'message_id', help='View message with id', nargs="?", type=int
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


class EncryptedFile(io.RawIOBase):
    iterob = None
    _left = b""

    def __init__(self, fencryptor, nonce, fileob, headers="\n"):
        self.iterob = self.init_iter(fencryptor, nonce, fileob, headers)

    @staticmethod
    def init_iter(fencryptor, nonce, fileob, headers):
        yield b"%b\0" % nonce
        yield fencryptor.update(b"%b\n" % headers)
        chunk = fileob.read(512)
        while chunk:
            assert isinstance(chunk, bytes)
            yield fencryptor.update(chunk)
            chunk = fileob.read(512)
        yield fencryptor.finalize()
        yield fencryptor.tag

    def read(self, size=-1):
        if size == -1:
            return b"".join(self.iterob)
        elif size < len(self._left):
            ret, self._left = self._left[:size], self._left[size:]
            return ret
        else:
            for chunk in self.iterob:
                self._left += chunk
                if len(self._left) >= size:
                    break
            ret, self._left = self._left[:size], self._left[size:]
            return ret


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


def get_pages(graph):
    tmp = list(graph.query(
        """
            SELECT ?pages
            WHERE {
                ?base spkc:pages.num_pages ?pages .
            }
        """,
        initNs={"spkc": spkcgraph}
    ))
    pages = tmp[0][0].toPython()
    return pages


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


def action_send(argv, priv_key, pub_key_hash, src_keys, session, g_src):
    component_uriref, src_options = analyze_src(g_src)
    if not component_uriref:
        parser.exit(1, "Source cannot create messages, logged in?")

    dest_url = merge_get_url(argv.dest, raw="embed", search="_type=PostBox")
    response_dest = session.get(dest_url)
    if not response_dest.ok:
        logger.info("Dest returned error: %s", response_dest.text)
        parser.exit(1, "retrieval failed, invalid url?\n")
    dest = {}
    g_dest = Graph()
    g_dest.parse(data=response_dest.content, format="turtle")
    pages = get_pages(g_dest)
    for page in range(2, pages+1):
        with session.get(
            merge_get_url(dest_url, page=page), headers={
                "X-TOKEN": argv.token
            }
        ) as response:
            response.raise_for_status()
            g_dest.parse(data=response.content, format="turtle")
    dest_postbox_url, webref_url, dest, dest_hash_algo = analyse_dest(g_dest)

    bdomain = dest_postbox_url.split("?", 1)[0]
    result_dest, _, dest_keys = argv.attestation.check(
        bdomain,
        map(
            lambda x: (x["key"], x["signature"]),
            dest.values()
        ),
        algo=dest_hash_algo
    )
    if result_dest == AttestationResult.domain_unknown:
        logger.info("add domain: %s", bdomain)
        argv.attestation.add(
            bdomain,
            map(
                lambda x: (x["key"], x["signature"]),
                dest.values()
            ),
            algo=dest_hash_algo
        )
    elif result_dest == AttestationResult.error:
        logger.critical("Dest base url contains invalid keys.")
        parser.exit(1, "dest contains invalid keys\n")

    # 256 bit
    aes_key = os.urandom(32)
    nonce = os.urandom(13)
    fencryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()
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
            src_key_list[
                "%s=%s" % (argv.src_hash_algo.name, k[0].hex())
            ] = base64.urlsafe_b64encode(enc).decode("ascii")
    else:
        enc = priv_key.public_key().encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=argv.src_hash_algo),
                algorithm=argv.src_hash_algo, label=None
            )
        )
        # encrypt decryption key
        src_key_list[
            "%s=%s" % (argv.src_hash_algo.name, pub_key_hash)
        ] = base64.urlsafe_b64encode(enc).decode("ascii")

    for k in dest_keys:
        enc = k[1].encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=dest_hash_algo),
                algorithm=dest_hash_algo, label=None
            )
        )
        # encrypt decryption key
        dest_key_list[
            "%s=%s" % (dest_hash_algo.name, k[0].hex())
        ] = base64.urlsafe_b64encode(enc).decode("ascii")
    headers = b"SPKC-Type: %b\n" % MessageType.file

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
            "encrypted_content": EncryptedFile(
                fencryptor, nonce, argv.file, headers
            )
        }
    )
    if not response.ok or message_create_url == response.url:
        logger.error("Message creation failed: %s", response.text)
        parser.exit(1, "Message creation failed: %s" % response.text)
    g = Graph()
    g.parse(data=response.content, format="html")
    fetch_url = list(map(lambda x: x.value, g.query(
        """
            SELECT ?value
            WHERE {
                ?property spkc:name ?name ;
                          spkc:value ?value .
            }
        """,
        initNs={"spkc": spkcgraph},
        initBindings={
            "name": Literal(
                "fetch_url", datatype=XSD.string
            )
        }
    )))

    tokens = list(map(lambda x: x.value, g.query(
        """
            SELECT ?value
            WHERE {
                ?property spkc:name ?name ;
                          spkc:value ?value .
            }
        """,
        initNs={"spkc": spkcgraph},
        initBindings={
            "name": Literal(
                "tokens", datatype=XSD.string
            )
        }
    )))

    if not fetch_url or not tokens:
        logger.error("Message creation failed: %s", response.text)
        parser.exit(1, "Message creation failed")
    # extract url
    response_dest = session.post(
        webref_url, data={
            "url": merge_get_url(fetch_url[0], token=str(tokens[0])),
            "key_list": json.dumps(dest_key_list)
        }
    )
    response_dest.raise_for_status()

    if not response_dest.ok:
        logger.error("Sending message failed: %s", response_dest.text)
        parser.exit(1, "Sending message failed")


def action_view(argv, priv_key, pem_public, own_url, session, g_message):
    if argv.message_id is not None:
        assert isinstance(argv.message_id, int)
        result = list(g_message.query(
            """
                SELECT DISTINCT ?base ?hash_algorithm ?type
                WHERE {
                    ?base a <https://spkcspider.net/static/schemes/spkcgraph#spkc:Content> ;
                                  spkc:type ?type ;
                                  spkc:properties ?propalg , ?propid .
                    ?propid spkc:name ?idname ;
                            spkc:value ?idvalue .
                    ?propalg spkc:name ?algname ;
                             spkc:value ?hash_algorithm .
                }
            """,  # noqa E501
            initNs={"spkc": spkcgraph},
            initBindings={
                "idvalue": Literal(argv.message_id),
                "algname": Literal(
                    "hash_algorithm", datatype=XSD.string
                ),
                "idname": Literal(
                    "id", datatype=XSD.string
                ),

            }
        ))
        if not result or result[0].type.toPython() not in {
            "WebReference", "MessageContent"
        }:
            parser.exit(0, "message not found\n")
        pub_key_hasher = getattr(
            hashes, result[0].hash_algorithm.upper()
        )()

        digest = hashes.Hash(pub_key_hasher, backend=default_backend())
        digest.update(pem_public)
        pub_key_hashalg = "%s=%s" % (
            pub_key_hasher.name,
            digest.finalize().hex()
        )
        retrieve_url = merge_get_url(
            replace_action(
                result[0].base, "message/"
            )
        )
        if argv.action == "peek":
            response = session.get(
                retrieve_url, stream=True, headers={
                    "X-TOKEN": argv.token
                }
            )
        else:
            response = session.post(
                retrieve_url, stream=True, headers={
                    "X-TOKEN": argv.token
                }, data={
                    "keyhash": pub_key_hashalg
                }
            )
        if not response.ok:
            logger.info("Message retrieval failed: %s", response.text)
            parser.exit(0, "message could not be fetched\n")
        key_list = json.loads(response.headers["X-KEYLIST"])
        key = key_list.get(pub_key_hashalg, None)
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

        headblock = b""
        fdecryptor = None
        eparser = emailparser.BytesFeedParser(policy=policy.default)
        headers = None
        for chunk in response.iter_content(chunk_size=256):
            blob = None
            if not fdecryptor:
                headblock = b"%b%b" % (headblock, chunk)
                if b"\0" in headblock:
                    nonce, headblock = headblock.split(b"\0", 1)
                    fdecryptor = Cipher(
                        algorithms.AES(decrypted_key),
                        modes.GCM(nonce),
                        backend=default_backend()
                    ).decryptor()
                    blob = fdecryptor.update(headblock[:-16])
                    headblock = headblock[-16:]
                else:
                    continue
            else:
                blob = fdecryptor.update(
                    b"%b%b" % (headblock, chunk[:-16])
                )
                headblock = chunk[-16:]
            if not headers:
                if b"\n\n" not in blob:
                    eparser.feed(blob)
                    continue
                headersrest, blob = blob.split(b"\n\n", 1)
                eparser.feed(headersrest)
                headers = eparser.close()
                # check  what to do
                t = headers.get("SPKC-Type", MessageType.email)
                if t == MessageType.email:
                    argv.file.write(headers.as_bytes(
                        unixfrom=True,
                        policy=policy.SMTP
                    ))
            argv.file.write(blob)
        argv.file.write(fdecryptor.finalize_with_tag(headblock))
    else:
        queried_webrefs = {}
        queried_messages = {}
        g_message.serialize(destination='output.txt', format='turtle')
        for i in g_message.query(
            """
            SELECT DISTINCT ?base ?idvalue ?namevalue ?type
            WHERE {
                ?base a <https://spkcspider.net/static/schemes/spkcgraph#spkc:Content> ;
                   spkc:type ?type ;
                   spkc:properties ?propname , ?propid .
                ?propid spkc:name ?idname ;
                        spkc:value ?idvalue .
                ?propname spkc:name ?namename ;
                          spkc:value ?namevalue .
            }
        """,  # noqa E501
            initNs={"spkc": spkcgraph},
            initBindings={
                "idname": Literal(
                    "id", datatype=XSD.string
                ),
                "namename": Literal(
                    "name", datatype=XSD.string
                ),

            }
        ):
            if i.type.toPython() == "WebReference":
                queried = queried_webrefs
            elif i.type.toPython() == "MessageContent":
                queried = queried_messages
            else:
                continue
            queried.setdefault(str(i.base), {})
            queried[str(i.base)]["id"] = i.idvalue
            queried[str(i.base)]["name"] = i.namevalue
        print("Received Messages:")
        for i in sorted(queried_webrefs.values(), key=lambda x: x["id"]):
            print(i["id"], i["name"])

        print("Own Messages:")
        for i in sorted(queried_messages.values(), key=lambda x: x["id"]):
            print(i["id"], i["name"])


def action_check(argv, priv_key, pub_key_hash, session, g):
    src = {}

    postbox = None

    for i in g.query(
        """
            SELECT DISTINCT
            ?postbox ?key_base ?key_base_prop ?key_name ?key_value
            WHERE {
                ?postbox spkc:properties ?postbox_prop .
                ?postbox_prop spkc:name ?postbox_prop_name .
                ?postbox_prop spkc:value ?key_base .
                ?key_base spkc:properties ?key_base_prop .
                ?key_base_prop spkc:name ?key_name ;
                               spkc:value ?key_value .
            }
        """,
        initNs={"spkc": spkcgraph},
        initBindings={
            "postbox_prop_name": Literal(
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
        pub_key_hash_bin = bytes.fromhex(pub_key_hash)
        can_fix = list(filter(lambda x: x[0] == pub_key_hash_bin, errored))
        if not argv.fix:
            if can_fix and postbox:
                print("Can fix signature")
        else:
            if not can_fix or not postbox:
                return ", ".join(map(lambda x: x[0].hex(), errored))

            postbox_update = replace_action(
                postbox, "update/"
            )
            # retrieve token
            response = session.get(
                postbox_update, headers={
                    "X-TOKEN": argv.token
                }
            )
            g_token = Graph()
            g_token.parse(data=response.content, format="html")
            csrftoken = list(g_token.objects(
                predicate=spkcgraph["csrftoken"])
            )[0]
            fields = dict(map(
                lambda x: (x[0].toPython(), x[1].toPython()),
                g_token.query(
                    """
                        SELECT DISTINCT ?fieldname ?value
                        WHERE {
                            ?base spkc:fieldname ?fieldname .
                            ?base spkc:value ?value .
                        }
                    """,
                    initNs={"spkc": spkcgraph},
                )
            ))
            breakpoint()

            fields["signatures"] = \
                list(filter(
                    lambda x: x not in can_fix,
                    json.loads(fields["signatures"])
                ))
            for key in can_fix:
                # currently only one priv key is supported
                signature = priv_key.sign(
                    src_activator_value,
                    padding.PSS(
                        mgf=padding.MGF1(src_hash),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    src_hash
                )
                fields["signatures"].append(
                    {
                        "hash": key[0].hex(),
                        "signature": "{}={}".format(
                            src_hash.name,
                            base64.urlsafe_b64encode(signature).decode("ascii")
                        )
                    }
                )

            fields["signatures"] = json.dumps(fields["signatures"])
            # update
            response = session.post(
                postbox_update, data=fields, headers={
                    "X-CSRFToken": csrftoken,
                    "X-TOKEN": argv.token
                }
            )
            if not response.ok:
                logger.error("Repair failed: %s", response.text)
                parser.exit(1, "repair failed\n")
            logger.debug("Repair succeeded")
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
        logging.basicConfig(level=logging.DEBUG)
    elif argv.verbose >= 1:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.WARNING)
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
                argv.url, raw="embed", search="_type=PostBox"
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
        pages = get_pages(g)
        for page in range(2, pages+1):
            with s.get(
                merge_get_url(own_url, page=page), headers={
                    "X-TOKEN": argv.token
                }
            ) as response:
                response.raise_for_status()
                g.parse(data=response.content, format="turtle")
        src = {}

        for i in g.query(
            """
                SELECT
                ?postbox ?postbox_value ?key_name ?key_value
                WHERE {
                    ?postbox spkc:properties ?property .
                    ?property spkc:name ?postbox_name ;
                              spkc:value ?postbox_value .
                    ?postbox_value spkc:properties ?key_base_prop .
                    ?key_base_prop spkc:name ?key_name ;
                                   spkc:value ?key_value .
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
                argv, priv_key, pub_key_hash, src_keys, s, g
            )
        elif argv.action in {"view", "peek"}:
            return action_view(argv, priv_key, pem_public, own_url, s, g)
        elif argv.action == "check":
            ret = action_check(argv, priv_key, pub_key_hash, s, g)
            if ret is not True:
                parser.exit(2, "check failed: %s\n" % ret)
            print("check successful")


if __name__ == "__main__":
    main(sys.argv[1:])
