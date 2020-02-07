__all__ = ["PostBox"]


import base64
import json
import logging
import os
import tempfile
import io
from email import parser as emailparser
from email import policy

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from rdflib import XSD, Graph, Literal
from spkcspider.constants import spkcgraph
from spkcspider.utils.urls import merge_get_url, replace_action
from spkcspider.utils.misc import EncryptedFile

from spider_messaging.constants import (
    AccessMethod, AttestationResult, MessageType, SendType
)
from spider_messaging.utils.graph import analyse_dest, get_hash, get_pages

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

    def _send_dest(self, aes_key, fetch_url, dest):
        dest_url = merge_get_url(
            dest, raw="embed", search="_type=PostBox")
        response_dest = self.session.get(dest_url)
        if not response_dest.ok:
            logger.info("Dest returned error: %s", response_dest.text)
            raise Exception("retrieval failed, invalid url?")
        dest = {}
        g_dest = Graph()
        g_dest.parse(data=response_dest.content, format="turtle")
        for page in get_pages(g_dest):
            with self.session.get(
                merge_get_url(dest_url, page=page)
            ) as response:
                response.raise_for_status()
                g_dest.parse(data=response.content, format="turtle")
        dest_postbox_url, webref_url, dest, dest_hash_algo, attestation = \
            analyse_dest(g_dest)

        bdomain = dest_postbox_url.split("?", 1)[0]
        result_dest, _, dest_keys = self.attestation_checker.check(
            bdomain,
            map(
                lambda x: (x["key"], x["signature"]),
                dest.values()
            ), attestation=attestation,
            algo=dest_hash_algo, auto_add=True
        )
        if result_dest == AttestationResult.domain_unknown:
            logger.info("add domain: %s", bdomain)
            self.attestation_checker.attestation.add(
                bdomain,
                dest_keys,
                algo=dest_hash_algo
            )
        elif result_dest == AttestationResult.error:
            logger.critical("Dest base url contains invalid keys.")
            raise Exception("dest contains invalid keys\n")

        dest_key_list = {}

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

        response_dest = self.session.post(
            webref_url, data={
                "url": fetch_url,
                "key_list": json.dumps(dest_key_list)
            }
        )
        response_dest.raise_for_status()
        # return No

    def send(
        self, inp, receivers, headers=None, mode=SendType.shared, aes_key=None
    ):
        if not self.ok:
            raise
        if not hasattr(receivers, "__iter__"):
            receivers = [receivers]

        if isinstance(inp, (bytes, memoryview)):
            inp = io.BytesIO(bytes(inp))
        elif isinstance(inp, str):
            inp = io.BytesIO(inp.encode("utf8"))

        # 256 bit
        if not aes_key:
            aes_key = os.urandom(32)
        assert len(aes_key) == 32
        nonce = os.urandom(13)
        fencryptor = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(nonce),
            backend=default_backend()
        ).encryptor()
        src_key_list = {}
        if mode == SendType.stealth:
            pass
        elif mode == SendType.private:
            enc = self.priv_key.public_key().encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=self.hash_algo),
                    algorithm=self.hash_algo, label=None
                )
            )
            # encrypt decryption key
            src_key_list[
                "%s=%s" % (self.hash_algo.name, self.pub_key_hash)
            ] = base64.urlsafe_b64encode(enc).decode("ascii")
        elif mode == SendType.shared:
            for k in self.client_list:
                enc = k[1].encrypt(
                    aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=self.hash_algo),
                        algorithm=self.hash_algo, label=None
                    )
                )
                # encrypt decryption key
                src_key_list[
                    "%s=%s" % (self.hash_algo.name, k[0].hex())
                ] = base64.urlsafe_b64encode(enc).decode("ascii")
        else:
            raise NotImplementedError()

        headers = b"SPKC-Type: %b\n" % MessageType.file

        # remove raw as we parse html
        message_create_url = merge_get_url(
            replace_action(
                self.url, "add/MessageContent/"
            ), raw=None
        )
        response = self.session.get(
            message_create_url, headers={
                "X-TOKEN": self.token
            }
        )
        if not response.ok:
            logger.error("retrieval csrftoken failed: %s", response.text)
            raise
        g = Graph()
        g.parse(data=response.content, format="html")
        csrftoken = list(g.objects(predicate=spkcgraph["csrftoken"]))[0]
        # create message object
        response = self.session.post(
            message_create_url, data={
                "own_hash": self.hash_key_public,
                "key_list": json.dumps(src_key_list),
                "amount_tokens": len(receivers)
            }, headers={
                "X-CSRFToken": csrftoken,
                "X-TOKEN": self.token  # only for src
            },
            files={
                "encrypted_content": EncryptedFile(
                    fencryptor, nonce, inp, headers
                )
            }
        )
        if not response.ok or message_create_url == response.url:
            logger.error("Message creation failed: %s", response.text)
            raise
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
            raise Exception("Message creation failed")
        fetch_url = fetch_url[0].toPython()
        for receiver, token in zip(receivers, tokens):
            furl = merge_get_url(fetch_url, token=token)
            try:
                self._send_dest(aes_key, furl, receiver)
            except Exception as exc:
                logger.exception(exc)
                # for autoremoval simulate access
                self.session.get(furl)

    def receive(
        self, message_id, outfp=None, access_method=AccessMethod.view,
        extra_keys=None, max_size=None
    ):
        if not self.ok:
            raise

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
                merge_get_url(self.url, raw="embed", page=page)
            ) as response:
                response.raise_for_status()
                graph.parse(data=response.content, format="turtle")
        result = list(graph.query(
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
                "idvalue": Literal(message_id),
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
            raise Exception("No Message")
        hash_algo = getattr(
            hashes, result[0].hash_algorithm.upper()
        )()

        if not outfp:
            outfp = tempfile.TempFile()

        digest = hashes.Hash(hash_algo, backend=default_backend())
        digest.update(self.pem_key_public)
        pub_key_hashalg = "%s=%s" % (
            hash_algo.name,
            digest.finalize().hex()
        )
        retrieve_url = merge_get_url(
            replace_action(
                result[0].base,
                "bypass/" if access_method == AccessMethod.view else "message/"
            )
        )
        data = {
            "max_size": max_size or ""
        }
        if access_method == AccessMethod.view:
            data["keyhash"] = pub_key_hashalg
        response = self.session.post(
            retrieve_url, stream=True, headers={
                "X-TOKEN": self.token
            }, data=data
        )
        if not response.ok:
            logger.info("Message retrieval failed: %s", response.text)
            raise
        key_list = json.loads(response.headers["X-KEYLIST"])
        key = key_list.get(pub_key_hashalg, None)
        if not key:
            raise Exception("message not for me")
        decrypted_key = self.priv_key.decrypt(
            base64.urlsafe_b64decode(key),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hash_algo),
                algorithm=hash_algo,
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
                    outfp.write(headers.as_bytes(
                        unixfrom=True,
                        policy=policy.SMTP
                    ))
            outfp.write(blob)
        outfp.write(fdecryptor.finalize_with_tag(headblock))
        return outfp, decrypted_key

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
