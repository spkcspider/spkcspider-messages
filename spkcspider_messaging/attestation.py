
import binascii
import sqlite3
import base64
import enum
from itertools import repeat

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.x509 import load_pem_x509_certificate


class AttestationResult(enum.IntEnum):
    success = 0
    partial_success = 1
    domain_unknown = 2
    error = 3


def _load_public_key(key):
    defbackend = default_backend()
    if isinstance(key, str):
        key = key.encode("utf8")
    elif hasattr(key, "public_bytes"):
        return key
    elif hasattr(key, "public_key"):
        return key.public_key()
    if isinstance(key, str):
        key = key.encode("utf8")
    try:
        return load_pem_x509_certificate(
            key, defbackend
        ).public_key()
    except ValueError:
        try:
            return load_pem_public_key(
                key, defbackend
            )
        except ValueError:
            raise


def _extract_hash_key(val, algo=None, use_hash=True):
    key = None
    signature = None
    if isinstance(val, (tuple, list)):
        v = val[0]
        if len(val) >= 2:
            try:
                key = _load_public_key(val[1])
                if not use_hash:
                    v = key
            except ValueError:
                if len(val) >= 3:
                    raise
                # activate second pattern
                v = _load_public_key(val[0])
                signature = val[1]
        if len(val) >= 3:
            signature = val[2]
    else:
        v = val

    if isinstance(v, bytes):
        return (v, key, signature)
    elif isinstance(v, str):
        v = v.split("=", 1)[-1]
        return (binascii.unhexlify(v), key, signature)
    elif hasattr(v, "public_key"):
        v = v.public_key()

    if hasattr(v, "public_bytes"):
        digest = hashes.Hash(algo, backend=default_backend())
        digest.update(
            v.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        return (
            digest.finalize(),
            v,
            signature
        )
    else:
        raise NotImplementedError()


def _extract_only_hash(val, algo=None, use_hash=True):
    return _extract_hash_key(val, algo=algo, use_hash=use_hash)[0]


class AttestationChecker(object):
    con = None

    def __init__(self, dbfile):
        self.con = sqlite3.connect(dbfile)
        self.create()

    def __del__(self):
        self.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def create(self):
        cur = self.con.cursor()
        cur.execute(
            '''
            CREATE TABLE IF NOT EXISTS domain (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                url TEXT NOT NULL UNIQUE,
                attestation BLOB
            )
            '''
        )
        cur.execute(
            '''
            CREATE TABLE IF NOT EXISTS key (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                domain INTEGER NOT NULL,
                hash BLOB NOT NULL,
                FOREIGN KEY(domain) REFERENCES domain(id),
                UNIQUE(domain, hash)
            )
            '''
        )
        self.con.commit()

    def close(self):
        self.con.close()

    @classmethod
    def calc_attestation(cls, key_list, algo):
        """
            key_hashes:
                pairs (hash, key): use hash of key
                pairs (key, signature): autogeneration of missing key hash
                triples (hash, key, signature):
                    use hash of key
        """
        hasher = hashes.Hash(algo, backend=default_backend())
        for digest in sorted(map(
            lambda x: _extract_only_hash(x, algo),
            key_list
        )):
            hasher.update(digest)
        return hasher.finalize()

    @classmethod
    def check_signatures(cls, key_hashes, algo=None, attestation=None):
        """
            attestation: provide attestation instead of generating it again
            key_hashes:
                pairs (hash, key): fails
                pairs (key, signature): autogeneration of missing key hash
                triples (hash, key, signature):
                    hash provided as first argument (more efficient)
        """
        key_hashes = [
             _extract_hash_key(x, algo) for x in key_hashes
        ]

        if not attestation and algo:
            attestation = cls.calc_attestation(key_hashes, algo)
        elif isinstance(attestation, str):
            attestation = base64.urlsafe_b64decode(attestation)
        elif not attestation:
            raise ValueError("Provide either attestation or hash algo")
        errored = []
        for entry in key_hashes:
            key = entry[1]
            try:
                hashalgo, signature = entry[2].split("=", 1)
                hashalgo = getattr(hashes, hashalgo.upper())()
                key.verify(
                    base64.urlsafe_b64decode(signature),
                    attestation,
                    padding.PSS(
                        mgf=padding.MGF1(hashalgo),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashalgo
                )
            except (InvalidSignature, ValueError):
                errored.append(entry)
                continue
        return (attestation, errored)

    def add(
        self, domain, hash_keys, attestation=None, algo=None, _cur=None
    ):
        """
            attestation: provide attestation instead of generating it again
            hash_keys:
                string/bytes: use as hash
                pairs (hash, key): use hash
                pairs (key, signature): calc hash
                triples (hash, key, signature): use hash
        """
        hash_keys = list(map(
            lambda x: _extract_hash_key(x, algo),
            hash_keys
        ))
        if isinstance(attestation, str):
            attestation = base64.urlsafe_b64decode(attestation)
        elif not attestation and algo:
            attestation = self.calc_attestation(hash_keys, algo)
        if _cur:
            cursor = _cur
        else:
            cursor = self.con.cursor()
        if attestation is None:
            cursor.execute("""
                INSERT OR IGNORE INTO domain (url) VALUES(?)
            """, (domain, ))
        else:
            if not attestation:
                attestation = None
            cursor.execute("""
                INSERT OR REPLACE INTO domain (url, attestation) VALUES(?, ?)
            """, (domain, attestation))

        domainid = self.con.execute("""
            SElECT id, attestation FROM domain WHERE url=?
        """, (domain,)).fetchone()[0]

        cursor.executemany("""
            INSERT OR IGNORE INTO key (domain, hash)
            VALUES(?, ?);
        """, zip(repeat(domainid), map(lambda x: x[0], hash_keys)))
        self.con.commit()

    def check(
        self, domain, hash_keys, attestation=None, algo=None, auto_add=True
    ):
        """
            attestation: provide attestation
            hash_keys:
                pairs (key, signature): check also signature
                triples (hash, key, signature): check signature, recalc
        """
        hash_keys = list(map(
            lambda x: _extract_hash_key(x, algo, use_hash=False),
            hash_keys
        ))
        errors = []
        only_hashes = set(map(lambda x: x[0], hash_keys))
        if isinstance(attestation, str):
            attestation = base64.urlsafe_b64decode(attestation)
        elif not attestation and algo:
            attestation = self.calc_attestation(hash_keys, algo)

        if attestation:
            errors = self.check_signatures(
                hash_keys, attestation=attestation
            )[1]
            if errors:
                return AttestationResult.error

        domain_row = self.con.execute("""
            SElECT id, attestation FROM domain WHERE url=?
        """, (domain,)).fetchone()
        if not domain_row:
            if auto_add:
                self.add(domain, hash_keys, attestation=attestation)
                return AttestationResult.domain_unknown
            else:
                return AttestationResult.error
        if attestation and domain_row[1] == attestation:
            return AttestationResult.success

        # hack lists
        old_hashes = self.con.execute("""
            SELECT hash FROM key WHERE domain=? AND hash IN ({})
        """.format(("?, "*len(only_hashes)).rstrip(", ")),
            (domain_row[0], *only_hashes)
        )
        old_hashes = set(map(lambda x: x[0], old_hashes.fetchall()))
        if len(old_hashes) == 0:
            return AttestationResult.error
        if old_hashes == only_hashes:
            return AttestationResult.success
        if auto_add:
            # hack lists
            _cur = self.con.cursor()
            _cur.execute("""
                DELETE FROM key WHERE domain=? AND hash NOT IN ({})
            """.format(("?, "*len(only_hashes)).rstrip(", ")),
                (domain_row[0], *only_hashes)
            )
            if only_hashes.issubset(old_hashes):
                self.con.commit()
                return AttestationResult.success
            self.add(
                domain, only_hashes.difference(old_hashes),
                attestation=attestation, _cur=_cur
            )
        if only_hashes.issubset(old_hashes):
            return AttestationResult.success
        return AttestationResult.partial_success
