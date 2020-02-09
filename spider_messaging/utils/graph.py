__all__ = ["get_pages", "get_postboxes", "map_hashes"]

from rdflib import XSD, Literal, URIRef

from spkcspider.constants import spkcgraph
from cryptography.hazmat.primitives import hashes


def get_pages(graph):
    tmp = list(map(lambda x: x, graph.query(
        """
            SELECT ?action_view ?pages
            WHERE {
                ?base spkc:pages.num_pages ?pages ;
                      spkc:action:view ?action_view .
            }
        """,
        initNs={"spkc": spkcgraph}
    )))
    url = str(tmp[0].action_view)
    pages = tmp[0].pages.toPython()

    read_pages = set(map(lambda x: x[0].toPython(), graph.query(
        """
            SELECT ?page
            WHERE {
                ?base spkc:pages.current_page ?page .
            }
        """,
        initNs={"spkc": spkcgraph}
    )))

    def _iter():
        for page in range(1, pages+1):
            if page not in read_pages:
                yield page
    return url, _iter()


def map_hashes(graph):
    raise NotImplemented
    # TODO: calculate via key objects
    return dict(map(
        lambda x: (x.pub_hash, x.norm_hash),
        graph.query(
            """
                SELECT ?pub_hash ?norm_hash
                WHERE {
                    ?key spkc:type ?key_type;
                        spkc:properties ?property1, ?property2 .
                    ?property1 spkc:name ?pub_name ;
                            spkc:value  ?pub_hash .
                    ?property2 spkc:name ?norm_name ;
                            spkc:value  ?norm_hash .
                }
            """,
            initNs={"spkc": spkcgraph},
            initBindings={
                "key_type": Literal(
                    "Key", datatype=XSD.string
                ),
                "pub_name": Literal(
                    "pubkeyhash", datatype=XSD.string
                ),
                "norm_name": Literal(
                    "hash", datatype=XSD.string
                )
            }
        )
    ))


def get_postboxes(graph, url=None):
    postboxes = {}
    find_postbox_params = {
        "postbox_type": Literal(
            "PostBox", datatype=XSD.string
        ),
        "postbox_name": Literal(
            "signatures", datatype=XSD.string
        )
    }
    if url:
        find_postbox_params["postbox"] = URIRef(url.split("?", 1)[0])

    for i in graph.query(
        """
            SELECT
            ?postbox ?name ?value
            WHERE {
                ?postbox spkc:type ?postbox_type;
                         spkc:properties ?property .
                ?property spkc:name ?name ;
                          spkc:value  ?value .
            }
        """,
        initNs={"spkc": spkcgraph},
        initBindings=find_postbox_params
    ):
        postbox = str(i.postbox)
        name = i.name.toPython()
        postboxes.setdefault(postbox, {})
        if name == "hash_algorithm":
            postboxes[postbox][name] = getattr(
                hashes, i.value.toPython().upper()
            )()
        else:
            postboxes[postbox][name] = i.value.toPython()

    uris = set(map(URIRef, postboxes.keys()))

    for uri in uris:
        postboxes[str(uri)]["signatures"] = {}
        src = postboxes[str(uri)]["signatures"]
        for i in graph.query(
            """
                SELECT
                ?key_base ?key_name ?key_value
                WHERE {
                    ?postbox spkc:properties ?property .
                    ?property spkc:name ?postbox_name ;
                              spkc:value ?key_base .
                    ?key_base spkc:properties ?key_base_prop .
                    ?key_base_prop spkc:name ?key_name ;
                                   spkc:value ?key_value .
                }
            """,
            initNs={"spkc": spkcgraph},
            initBindings={
                "postbox": uri,
                "postbox_name": Literal(
                    "signatures", datatype=XSD.string
                )
            }
        ):
            value = str(i.key_base)
            src.setdefault(value, {})
            src[value][str(i.key_name)] = i.key_value.toPython()
    return postboxes
