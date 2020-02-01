__all__ = ["PostBox"]


import logging

import requests
from rdflib import XSD, Graph, Literal
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from spider_messaging.constants import AttestationResult, SendType
from spkcspider.utils.urls import merge_get_url, replace_action

from spkcspider.constants import static_token_matcher, spkcgraph

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
                merge_get_url(self.url, raw="true"),
                headers={
                    "X-TOKEN": self.token or ""
                }
            )
            response.raise_for_status()
            graph = Graph()
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

    def send(self, ob, receivers, mode=SendType.shared):
        if not self.ok:
            raise
        pass

    def receive(self, id, peek=False, extra_keys=None, max_size=None):
        if not self.ok:
            raise

    def list_messages(self, limit_to=None):
        pass

    def check(self, url=None, graph=None):
        if not url or url == self.url:
            # TODO: after recheck update own state and client list
            result_own, errored, src_keys = self.attestation_checker.check(
                self.url,
                map(
                    lambda x: (x["key"], x["signature"]),
                    src.values()
                ),
                algo=self.hash_algo
            )
            if result_own == AttestationResult.domain_unknown:
                logger.critical(
                    "home url unknown, should not happen"
                )
            elif result_own != AttestationResult.success:
                logger.critical(
                    "Home base url contains invalid keys, hacked?"
                )

    def sign(self, url=None, token=None):
        pass

    @property
    def ok(self):
        return self.state in success_states
