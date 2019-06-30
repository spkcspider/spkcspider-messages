
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
    try:
        return load_pem_x509_certificate(
            key, defbackend
        ).public_key()
    except ValueError:
        try:
            return load_pem_public_key(
                key, defbackend
            ).public_key()
        except ValueError:
            raise


def _extract_hash_key(val):
    key = None
    signature = None
    if isinstance(val, (tuple, list)):
        v = val[0]
        key = _load_public_key(val[1])
        if len(val) >= 3:
            signature = val[2]
    else:
        v = val
    if isinstance(v, bytes):
        return (v, key, signature)
    elif isinstance(v, str):
        return (binascii.unhexlify(v), key, signature)


def _extract_only_hash(val):
    return _extract_hash_key[0]


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
        hasher = hashes.Hash(algo, backend=default_backend())
        for digest in sorted(map(_extract_only_hash, key_list)):
            hasher.update(digest)
        return hasher.finalize()

    @classmethod
    def check_signatures(cls, key_signatures, algo=None, attestation=None):
        """
            attestation: provide attestation instead of generating it again
            key_signatures:
                pairs (key, signature): autogeneration of missing key hash
                triples (hash, key, signature):
                    hash provided as first argument (more efficient)
        """
        defbackend = default_backend()

        if not attestation and algo:
            def _key_to_hash_helper(x):
                if len(x) == 3:
                    return x[0]
                digest = hashes.Hash(algo, backend=defbackend)
                digest.update(
                    _load_public_key(x[-2]).public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                )
                return digest.finalize()

            key_hashes = list(map(
                _key_to_hash_helper(key_signatures)
            ))
            attestation = cls.calc_attestation(key_hashes, algo)
        elif not attestation:
            raise ValueError("Provide either attestation or hash algo")
        errored = []
        for entry in key_signatures:
            key = entry[-2]
            hashalgo, signature = entry[-1].split("=", 1)
            hashalgo = getattr(hashes, hashalgo.upper())()
            try:
                key.verify(
                    base64.urlsafe_b64decode(signature),
                    attestation,
                    padding.PSS(
                        mgf=padding.MGF1(hashalgo),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashalgo
                )
            except InvalidSignature:
                errored.append(entry)
                continue
        return (attestation, errored)

    def add(self, domain, hash_keys, attestation=None, algo=None, _cur=None):
        if isinstance(attestation, str):
            attestation = attestation.decode("hex")
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
        """, zip(repeat(domainid), map(_extract_only_hash, hash_keys)))
        self.con.commit()

    def check(
        self, domain, hash_keys, attestation=None, algo=None, auto_add=True
    ):
        """
            attestation: provide attestation
            hash_keys:
                string/bytes: use as hash
                triples (hash, key, signature): check also signature
        """
        to_check = list(map(_extract_hash_key, hash_keys))
        only_hashes = set(map(_extract_only_hash, to_check))
        to_check = list(filter(
            lambda x: isinstance(x, (list, tuple)) and len(x) >= 3,
            to_check
        ))
        if isinstance(attestation, str):
            attestation = attestation.decode("hex")
        elif not attestation and algo:
            attestation = self.calc_attestation(hash_keys, algo)

        if to_check and attestation:
            to_check_result = self.check_signatures(
                to_check, attestation=attestation
            )
            if to_check_result[1]:
                return AttestationResult.error

        domain_row = self.con.execute("""
            SElECT id, attestation FROM domain WHERE url=?
        """, (domain,)).fetchone()
        if not domain_row:
            if auto_add:
                self.add(domain, only_hashes, attestation=attestation)
                return AttestationResult.domain_unknown
            else:
                return AttestationResult.domain_unknown
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
