
import binascii
import sqlite3
import base64
import enum
from itertools import repeat

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from .keys import load_public_key


class AttestationResult(enum.IntEnum):
    success = 0
    partial_success = 1
    domain_unknown = 2
    error = 3


def _extract_hash_key2(val, algo=None):
    key = None
    signature = None
    if isinstance(val, (tuple, list)):
        v = val[0]
        if len(val) >= 2:
            try:
                key = load_public_key(val[1])
            except ValueError:
                if len(val) >= 3:
                    raise
                # activate second pattern
                v = load_public_key(val[0])
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


def _extract_hash_key(val, algo=None, check_hash=False):
    ret = _extract_hash_key2(val, algo=algo)
    if check_hash and algo and ret[1] and len(val) >= 2:
        digest = hashes.Hash(algo, backend=default_backend())
        digest.update(
            ret[1].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        if ret[0] != digest.finalize():
            raise ValueError("Key does not match hash")
    return ret


def _extract_only_hash(val, algo=None, check_hash=False):
    return _extract_hash_key(val, algo=algo, check_hash=check_hash)[0]


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
    def calc_attestation(cls, key_list, algo, embed=False):
        """
            key_hashes:
                string/bytes: hashes
                pairs (hash, key): use hash of key
                pairs (key, signature): autogeneration of missing key hash
                triples (hash, key, signature):
                    use hash of key
        """
        hasher = hashes.Hash(algo, backend=default_backend())
        if not embed:
            def func(x):
                return _extract_only_hash(x, algo)
        else:
            def func(x):
                return x[0]
        for digest in sorted(map(func, key_list)):
            hasher.update(digest)
        return hasher.finalize()

    @classmethod
    def check_signatures(
        cls, key_hashes, algo=None, attestation=None, embed=False
    ):
        """
            attestation: provide attestation instead of generating it again
            key_hashes:
                pairs (hash, key): fails
                pairs (key, signature): autogeneration of missing key hash
                triples (hash, key, signature):
                    hash provided as first argument (more efficient)
        """
        if not embed:
            key_hashes = [
                 _extract_hash_key(x, algo) for x in key_hashes
            ]

        if not attestation and algo:
            attestation = cls.calc_attestation(key_hashes, algo, embed=True)
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
        return (attestation, errored, key_hashes)

    def add(
        self, domain, hash_keys, attestation=None, algo=None, _cur=None,
        embed=False
    ):
        """
            attestation: provide attestation instead of generating it again
            hash_keys:
                string/bytes: use as hash
                public_keys/certs: calc hash (in combination with algo)
                pairs (hash, key): use hash
                pairs (key, signature): calc hash
                triples (hash, key, signature): use hash
        """
        # _cur is used if embedding in check
        if not embed:
            hash_keys = [
                _extract_hash_key(x, algo, not _cur) for x in hash_keys
            ]
        if isinstance(attestation, str):
            attestation = base64.urlsafe_b64decode(attestation)
        elif not attestation and algo:
            attestation = self.calc_attestation(hash_keys, algo, embed=True)
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
        return hash_keys

    def check(
        self, domain, hash_keys, attestation=None, algo=None, auto_add=True,
        embed=False
    ):
        """
            attestation: provide attestation
            hash_keys:
                pairs (key, signature): check also signature
                triples (hash, key, signature): check signature, recalc
        """
        if not embed:
            hash_keys = [
                _extract_hash_key(x, algo, True) for x in hash_keys
            ]
        only_hashes = set(map(lambda x: x[0], hash_keys))
        if isinstance(attestation, str):
            attestation = base64.urlsafe_b64decode(attestation)
        elif not attestation and algo:
            attestation = self.calc_attestation(hash_keys, algo, embed=True)

        if attestation:
            result = self.check_signatures(
                hash_keys, attestation=attestation, embed=True
            )
            if result[1]:
                return result

        domain_row = self.con.execute("""
            SElECT id, attestation FROM domain WHERE url=?
        """, (domain,)).fetchone()
        if not domain_row:
            if auto_add:
                self.add(domain, hash_keys, attestation=attestation)
                return (
                    AttestationResult.domain_unknown, [], hash_keys
                )
            else:
                return (AttestationResult.error, [], hash_keys)
        if attestation and domain_row[1] == attestation:
            return (AttestationResult.success, [], hash_keys)

        # hack lists
        old_hashes = self.con.execute("""
            SELECT hash FROM key WHERE domain=? AND hash IN ({})
        """.format(("?, "*len(only_hashes)).rstrip(", ")),
            (domain_row[0], *only_hashes)
        )
        old_hashes = set(map(lambda x: x[0], old_hashes.fetchall()))
        if len(old_hashes) == 0:
            return (AttestationResult.error, [], hash_keys)
        if old_hashes == only_hashes:
            return (AttestationResult.success, [], hash_keys)
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
                return (AttestationResult.success, [], hash_keys)
            self.add(
                domain, only_hashes.difference(old_hashes),
                attestation=attestation, _cur=_cur, embed=True
            )
        if only_hashes.issubset(old_hashes):
            return (AttestationResult.success, [], hash_keys)
        return (AttestationResult.partial_success, [], hash_keys)
