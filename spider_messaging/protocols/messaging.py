__all__ = ["PostBox"]


import logging

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from rdflib import XSD, Graph, Literal
from spkcspider.constants import spkcgraph, static_token_matcher
from spkcspider.utils.urls import merge_get_url, replace_action

from spider_messaging.constants import AttestationResult, SendType
from spider_messaging.utils.graph import analyse_dest, analyze_src, get_pages

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

    def send(self, ob, receivers, mode=SendType.shared):
        if not self.ok:
            raise
        pass

    def receive(
        self, id, peek=False, bypass=False, extra_keys=None, max_size=None
    ):
        if not self.ok:
            raise

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

    def check(self, url=None, graph=None):
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
            self.state, errored, self.client_list = \
                self.attestation_checker.check(
                    self.url,
                    map(
                        lambda x: (x["key"], x["signature"]),
                        src.values()
                    ),
                    algo=self.hash_algo, auto_add=True
                )
            return self.state, errored, self.client_list
        # url was specified
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
        return self.attestation_checker.check(
            url,
            map(
                lambda x: (x["key"], x["signature"]),
                src.values()
            ),
            algo=self.hash_algo, auto_add=True
        )

    def sign(self, url=None, token=None):
        pass

    @property
    def ok(self):
        return self.state in success_states
