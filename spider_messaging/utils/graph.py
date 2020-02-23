__all__ = ["get_pages", "get_postboxes", "map_keys", "extract_property"]

import logging
from rdflib import XSD, Literal, URIRef

from spkcspider.constants import spkcgraph
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

from .keys import load_public_key


def extract_property(graph, name, url=None):
    bindings = {
        "prop_name": Literal(
            name, datatype=XSD.string
        )
    }
    if url:
        url = url.split("?", 1)[0]
        bindings["base"] = URIRef(url)
    ret = dict(map(lambda x: (x[0].toPython(), x[1].toPython()), graph.query(
        """
            SELECT ?base ?prop_val
            WHERE {

                _:p1 spkc:name ?prop_name ;
                     spkc:value ?prop_val .
                OPTIONAL {
                    _:p1 ^spkc:properties ?base .
                }
            }
        """,
        initNs={"spkc": spkcgraph},
        initBindings=bindings
    )))
    if url:
        return ret[url]
    else:
        return ret


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


def map_keys(graph, url=None, field="pubkeyhash", hash_algo=None):
    """
    [summary]

    Arguments:
        graph {[type]} -- [description]

    Keyword Arguments:
        url {[type]} -- [description] (default: {None})
        field {str} -- [description] (default: {"pubkeyhash"})
        hash_algo {None,False,algorithm} -- None: extract hash_algo from first entry, False: extract hash_algo for each entry, algorithm: use algorithm (default: {None})

    Returns:
        [type] -- [description]
    """  # noqa E502
    _map = {}
    _found_algos = set()
    bindings = {
        "key_type": Literal(
            "PublicKey", datatype=XSD.string
        ),
        "key_name": Literal(
            "key", datatype=XSD.string
        ),
        "hashalgo_name": Literal(
            "hash_algorithm", datatype=XSD.string
        ),
        "thirdparty_name": Literal(
            "thirdparty", datatype=XSD.string
        ),
    }
    if url:
        bindings["base"] = URIRef(url.split("?", 1)[0])
    for i in graph.query(
        """
            SELECT ?key_value ?hashalgo_value ?thirdparty_value
            WHERE {
                ?base spkc:contents | ( spkc:properties / spkc:value) ?kb .
                ?kb spkc:type ?key_type .
                _:p1 ^spkc:properties ?kb ;
                     spkc:name        ?key_name ;
                     spkc:value       ?key_value .
                _:p2 ^spkc:properties ?kb ;
                     spkc:name        ?hashalgo_name ;
                     spkc:value       ?hashalgo_value .
                OPTIONAL{
                    _:p3 ^spkc:properties ?kb ;
                         spkc:name        ?thirdparty_name ;
                         spkc:value       ?thirdparty_value .
                }

            }
        """,
        initNs={"spkc": spkcgraph},
        initBindings=bindings
    ):
        if hash_algo:
            _hash_algo = hash_algo
        else:
            _hash_algo = getattr(
                hashes, i.hashalgo_value.toPython().upper()
            )()
            if hash_algo is None:
                hash_algo = _hash_algo
            else:
                _found_algos.add(_hash_algo.name)
        digest = hashes.Hash(_hash_algo, backend=default_backend())
        digest.update(i.key_value.encode("utf8"))
        item = {
            "thirdparty":
                i.thirdparty_value.toPython() if i.thirdparty_value else False,
            "hash": digest.finalize()
        }
        try:
            item["pubkey"] = load_public_key(i.key_value)
            item["pubkeypem"] = item["pubkey"].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).strip()
            digest = hashes.Hash(_hash_algo, backend=default_backend())
            digest.update(item["pubkeypem"])
            item["pubkeyhash"] = digest.finalize()
            item["pubkeypem"] = item["pubkeypem"].decode("ascii")
        except Exception as exc:
            logging.info("Could not extract public key", exc_info=exc)
        if field not in item:
            continue
        _map[item.pop(field)] = item
    # if hash_algo was specified or None only one result is possible
    if hash_algo:
        return _map, hash_algo
    return _map, _found_algos


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
