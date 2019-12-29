#! /usr/bin/env python3

import argparse
import base64
import logging
import os
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from spider_messaging.keys import load_priv_key

logger = logging.getLogger(__name__)

parser = argparse.ArgumentParser(
    description='Sign keys'
)
parser.add_argument(
    '--hash', action='store', help="Hash algorithm", default="SHA512"
)
parser.add_argument(
    '--key', action='store', dest="key",
    default="key.priv", help='Private Key'
)
parser.add_argument(
    '--verbose', "-v", action='count', default=0,
    help='Verbosity'
)
parser.add_argument(
    'sign', help='Message to sign', nargs="+"
)


def main(argv):
    argv = parser.parse_args(argv)
    argv.hash = getattr(hashes, argv.hash)()
    if not os.path.exists(argv.key):
        argv.exit(1, "key does not exist")
    if argv.verbose >= 2:
        logger.setLevel(logging.DEBUG)
    elif argv.verbose >= 1:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)
    with open(argv.key, "rb") as f:
        pkey = load_priv_key(f.read())[0]

        if not pkey:
            argv.exit(1, "invalid key: %s" % argv.key)
    for tosign in argv.sign:
        signature = pkey.sign(
            base64.urlsafe_b64decode(tosign),
            padding.PSS(
                mgf=padding.MGF1(argv.hash),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            argv.hash
        )
        print("Signature:")
        print(
            argv.hash.name,
            base64.urlsafe_b64encode(signature).decode("ascii"),
            sep="="
        )


if __name__ == "__main__":
    main(sys.argv[1:])
