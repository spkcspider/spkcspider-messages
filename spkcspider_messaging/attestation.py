
import binascii
import sqlite3
import base64
import enum
from itertools import repeat

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class AttestationResult(enum.IntEnum):
    success = 0
    partial_success = 1
    domain_unknown = 2
    error = 3


def _de_hexlify(val):
    return val if isinstance(val, bytes) else binascii.unhexlify(val)


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
    def calc_attestation(cls, key_hashes, algorithm=None):
        if not algorithm:
            algorithm = hashes.SHA512()
        hasher = hashes.Hash(algorithm, backend=default_backend())
        for digest in sorted(map(_de_hexlify, key_hashes)):
            hasher.update(digest)
        return hasher.finalize()

    def add(self, domain, key_hashes, attestation=None, algo=None, _cur=None):
        if isinstance(attestation, str):
            attestation = base64.urlsafe_b64decode(attestation)
        elif not attestation and algo:
            attestation = self.calc_attestation(key_hashes, algo)
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
            if isinstance(attestation, str):
                attestation = base64.urlsafe_b64decode(attestation)
            cursor.execute("""
                INSERT OR REPLACE INTO domain (url, attestation) VALUES(?, ?)
            """, (domain, attestation))

        domainid = self.con.execute("""
            SElECT id, attestation FROM domain WHERE url=?
        """, (domain,)).fetchone()[0]

        cursor.executemany("""
            INSERT OR IGNORE INTO key (domain, hash)
            VALUES(?, ?);
        """, zip(repeat(domainid), map(_de_hexlify, key_hashes)))
        self.con.commit()

    def check(
        self, domain, key_hashes, attestation=None, algo=None, auto_add=True
    ):
        key_hashes = set(map(_de_hexlify, key_hashes))
        if isinstance(attestation, str):
            attestation = base64.urlsafe_b64decode(attestation)
        elif not attestation and algo:
            attestation = self.calc_attestation(key_hashes, algo)
        domain_row = self.con.execute("""
            SElECT id, attestation FROM domain WHERE url=?
        """, (domain,)).fetchone()
        if not domain_row:
            if auto_add:
                self.add(domain, key_hashes, attestation=attestation)
                return AttestationResult.domain_unknown
            else:
                return AttestationResult.domain_unknown
        if attestation and domain_row[1] == attestation:
            return AttestationResult.success

        # hack lists
        old_hashes = self.con.execute("""
            SElECT hash FROM key WHERE domain=? AND hash IN ({})
        """.format(("?, "*len(key_hashes)).rstrip(", ")),
            (domain_row[0], *key_hashes)
        )
        old_hashes = set(map(lambda x: x[0], old_hashes.fetchall()))
        if len(old_hashes) == 0:
            return AttestationResult.error
        if old_hashes == key_hashes:
            return AttestationResult.success
        if auto_add:
            # hack lists
            _cur = self.con.cursor()
            _cur.execute("""
                DELETE FROM key WHERE domain=? AND hash NOT IN ({})
            """.format(("?, "*len(key_hashes)).rstrip(", ")),
                (domain_row[0], *key_hashes)
            )
            if key_hashes.issubset(old_hashes):
                self.con.commit()
                return AttestationResult.success
            self.add(
                domain, key_hashes.difference(old_hashes),
                attestation=attestation, _cur=_cur
            )
        if key_hashes.issubset(old_hashes):
            return AttestationResult.success
        return AttestationResult.partial_success
