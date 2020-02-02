__all__ = ["PostBox"]


import base64
import json
import logging

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from rdflib import XSD, Graph, Literal
from spkcspider.constants import spkcgraph, static_token_matcher
from spkcspider.utils.urls import merge_get_url, replace_action

from spider_messaging.constants import AttestationResult, SendType
from spider_messaging.utils.graph import (
    analyse_dest, analyze_src, get_hash, get_pages
)

from . import AttestationChecker

logger = logging.getLogger(__name__)

success_states = {
    AttestationResult.success,
    AttestationResult.partial_success
}


class PostBox(object):
    attestation_checker = None
    session = None
    priv_key = None
    hash_algo = None
    pem_key_public = None
    hash_key_public = None
    url = None
    token = None
    client_list = None
    state = None

    def __init__(
        self, attestation_checker, priv_key, url=None, token=None, graph=None,
        session=None
    ):
        if isinstance(attestation_checker, AttestationChecker):
            self.attestation_checker = attestation_checker
        else:
            self.attestation_checker = AttestationChecker(attestation_checker)
        self.priv_key = priv_key
        self.pem_key_public = self.priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.url = url.split("?", 1)[0] if url else None
        self.update(token, graph, session)

    def update(self, token=None, graph=None, session=None):
        if session:
            self.session = session
        elif session is False or not self.session:
            self.session = requests.Session()
        if token:
            self.token = token
        if not graph:
            assert self.url
            response = self.session.get(
                merge_get_url(self.url, raw="embed"),
                headers={
                    "X-TOKEN": self.token or ""
                }
            )
            response.raise_for_status()
            graph = Graph()
            graph.parse(data=response.content, format="turtle")
        for page in get_pages(graph):
            with self.session.get(
                merge_get_url(self.url, raw="embed", page=page), headers={
                    "X-TOKEN": self.token or ""
                }
            ) as response:
                response.raise_for_status()
                graph.parse(data=response.content, format="turtle")
        src = {}
        for i in graph.query(
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
            url = str(i.postbox)
            value = str(i.postbox_value)
            src.setdefault(url, {})
            src[url].setdefault(value, {})
            src[url][value][str(i.key_name)] = i.key_value
        if not self.url:
            if len(src) != 1:
                raise ValueError("No postbox found/more than one found")
            self.url, src = list(src.items())[0]
        else:
            src = src[self.url]

        self.hash_algo = getattr(
            hashes, next(iter(src.values()))["hash_algorithm"].upper()
        )()

        digest = hashes.Hash(self.hash_algo, backend=default_backend())
        digest.update(self.pem_key_public)
        self.hash_key_public = digest.finalize()
        atth, errored, self.client_list = \
            self.attestation_checker.check_signatures(
                map(
                    lambda x: (x["key"], x["signature"]),
                    src.values()
                ),
                algo=self.hash_algo
            )
        errored = set(map(lambda x: x[0], errored))
        own_key_found = list(filter(
            lambda x: x[0] == self.hash_key_public,
            self.client_list
        ))
        if not own_key_found:
            raise ValueError("Own key was not found")
        if self.hash_key_public in errored:
            self.state = AttestationResult.error
        else:
            if errored:
                self.state = AttestationResult.partial_success
            else:
                self.state = AttestationResult.success
            # auto add if signed by own key
            self.attestation_checker.add(
                self.url, self.client_list, self.hash_algo, attestation=atth
            )

    def send(self, ob, receivers, headers=None, mode=SendType.shared):
        if not self.ok:
            raise
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
        for page in get_pages(g_dest):
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

    def receive(
        self, id, peek=False, bypass=False, extra_keys=None, max_size=None
    ):
        if not self.ok:
            raise
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

    def list_messages(self):
        queried_webrefs = {}
        queried_messages = {}
        response = self.session.get(
            merge_get_url(self.url, raw="embed"),
            headers={
                "X-TOKEN": self.token or ""
            }
        )
        response.raise_for_status()
        graph = Graph()
        graph.parse(data=response.content, format="turtle")
        for i in graph.query(
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
        return (queried_webrefs, queried_messages)

    def check(self, url=None):
        if not url or url == self.url:
            response = self.session.get(
                merge_get_url(self.url, raw="embed"),
                headers={
                    "X-TOKEN": self.token or ""
                }
            )
            response.raise_for_status()
            graph = Graph()
            graph.parse(data=response.content, format="turtle")
            for page in get_pages(graph):
                with self.session.get(
                    merge_get_url(self.url, raw="embed", page=page), headers={
                        "X-TOKEN": self.token or ""
                    }
                ) as response:
                    response.raise_for_status()
                    graph.parse(data=response.content, format="turtle")
        else:
            response = self.session.get(
                merge_get_url(url, raw="embed")
            )
            response.raise_for_status()
            graph = Graph()
            graph.parse(data=response.content, format="turtle")
            for page in get_pages(graph):
                response = self.session.get(
                    merge_get_url(self.url, raw="embed", page=page)
                )
                response.raise_for_status()
                graph.parse(data=response.content, format="turtle")

        hash_algo = get_hash(graph)
        a_calculated = self.attestation_checker.calc_attestation(
            self.client_list, algo=hash_algo, embed=True
        )
        a_found = list(graph.query(
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
        ))[0][0]
        if base64.urlsafe_b64decode(a_found.value) != a_calculated:
            raise Exception(
                "activator doesn't match shown activator"
            )

        src = {}
        for i in graph.query(
            """
                SELECT
                ?postbox ?key_name ?key_value
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
            value = str(i.postbox_value)
            src.setdefault(value, {})
            src[value][str(i.key_name)] = i.key_value
        if not url or url == self.url:
            self.state, errored, self.client_list = \
                self.attestation_checker.check(
                    self.url,
                    map(
                        lambda x: (x["key"], x["signature"]),
                        src.values()
                    ),
                    algo=hash_algo, auto_add=True
                )
            return self.state, errored, self.client_list
        else:
            return self.attestation_checker.check(
                url,
                map(
                    lambda x: (x["key"], x["signature"]),
                    src.values()
                ),
                algo=hash_algo, auto_add=True
            )

    def sign(self):
        postbox_update = replace_action(
            self.url, "update/"
        )
        # retrieve token
        response = self.session.get(
            postbox_update, headers={
                "X-TOKEN": self.token
            }
        )
        graph = Graph()
        graph.parse(data=response.content, format="html")
        csrftoken = list(graph.objects(
            predicate=spkcgraph["csrftoken"])
        )[0].toPython()
        hash_algo = get_hash(graph)
        a_calculated = self.attestation_checker.calc_attestation(
            self.client_list, algo=hash_algo, embed=True
        )
        a_found = list(graph.query(
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
        ))[0][0]
        if base64.urlsafe_b64decode(a_found.value) != a_calculated:
            raise Exception(
                "activator doesn't match shown activator"
            )

        fields = dict(map(
            lambda x: (x[0].toPython(), x[1].toPython()),
            graph.query(
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

        fields["signatures"] = []
        for key in self.client_list:
            if key[0] != self.hash_key_public:
                signature = key[2]
            else:
                # currently only one priv key is supported
                signature = self.priv_key.sign(
                    a_calculated,
                    padding.PSS(
                        mgf=padding.MGF1(self.hash_algo),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    self.hash_algo
                )
            if signature:
                fields["signatures"].append(
                    {
                        "hash": f"{self.hash_algo.name}={key[0].hex()}",
                        "signature": "{}={}".format(
                            self.hash_algo.name,
                            base64.urlsafe_b64encode(
                                signature
                            ).decode("ascii")
                        )
                    }
                )

        fields["signatures"] = json.dumps(fields["signatures"])
        # update
        response = self.session.post(
            postbox_update, data=fields, headers={
                "X-CSRFToken": csrftoken,
                "X-TOKEN": self.token
            }
        )
        response.raise_for_status()

    @property
    def ok(self):
        return self.state in success_states
