__all__ = ["get_pages", "analyze_src", "analyse_dest", "get_hash"]

import base64
from rdflib import XSD, Literal

from spkcspider.utils.urls import replace_action
from spkcspider.constants import spkcgraph
from cryptography.hazmat.primitives import hashes


def get_pages(graph):
    tmp = list(map(lambda x: x[0], graph.query(
        """
            SELECT ?pages
            WHERE {
                ?base spkc:pages.num_pages ?pages .
            }
        """,
        initNs={"spkc": spkcgraph}
    )))
    pages = tmp[0].toPython()

    read_pages = set(map(lambda x: x[0].toPython(), graph.query(
        """
            SELECT ?page
            WHERE {
                ?base spkc:pages.current_page ?page .
            }
        """,
        initNs={"spkc": spkcgraph}
    )))

    for page in range(1, pages+1):
        if page not in read_pages:
            yield page


def get_hash(graph, url=None):
    tmp = list(map(lambda x: x[0], graph.query(
        """
            SELECT ?hash_algo
            WHERE {
                ?postbox spkc:type ?postbox_type.
                ?postbox spkc:properties ?base .
                ?base spkc:name  ?prop_name ;
                      spkc:value ?hash_algo .
            }
        """,
        initNs={"spkc": spkcgraph},
        initBindings={
            "postbox_type": Literal(
                "PostBox", datatype=XSD.string
            ),
            "prop_name": Literal(
                "hash_algorithm", datatype=XSD.string
            )
        }
    )))
    return getattr(
        hashes, tmp[0].toPython().upper()
    )()


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
        return None, None, {}, None, None
    webref_url = replace_action(str(postbox_uriref), "push_webref/")

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
    attestation = list(graph.query(
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
    attestation = base64.urlsafe_b64decode(attestation[0][0])
    return (
        postbox_uriref, webref_url, domain_keys, hash_algo, attestation
    )
