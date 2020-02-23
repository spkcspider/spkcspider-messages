#!/usr/bin/env python3

import argparse
import logging
import os
import sys

from spkcspider.constants import static_token_matcher

from spider_messaging.constants import AccessMethod, MessageType
from spider_messaging.protocols.attestation import AttestationChecker
from spider_messaging.protocols.messaging import PostBox
from spider_messaging.utils.keys import load_priv_key

# import re


logger = logging.getLogger(__name__)

parser = argparse.ArgumentParser(
    description='Setup Email transport'
)
parser.add_argument(
    '--key', action='store', dest="key",
    default="key.priv", help='Private Key'
)
parser.add_argument(
    '--db', action='store', dest="attestation",
    default="attestation.sqlite3", help='DB for key attestation'
)
parser.add_argument(
    '--verbose', "-v", action='count', default=0,
    help='Verbosity'
)
parser.add_argument(
    'url', help='Postbox url with access token'
)
subparsers = parser.add_subparsers(dest='action', required=True)
view_parser = subparsers.add_parser("view")
view_parser.add_argument(
    '--file', help='Use file instead stdout', type=argparse.FileType('wb'),
    nargs="?", default=sys.stdout.buffer
)
view_parser.add_argument(
    '--max', help='Max size', type=int, default=None
)
view_parser.add_argument(
    'message_id', help='View message with id', nargs="?", type=int
)
peek_parser = subparsers.add_parser("peek")
peek_parser.add_argument(
    '--file', help='Use file instead stdout', type=argparse.FileType('wb'),
    nargs="?", default=sys.stdout.buffer
)
peek_parser.add_argument(
    '--max', help='Max size', type=int, default=None
)
peek_parser.add_argument(
    'message_id', help='View message with id', nargs="?", type=int
)
check_parser = subparsers.add_parser("check")
sign_parser = subparsers.add_parser("sign")
send_parser = subparsers.add_parser("send")
send_parser.add_argument(
    '--file', help='Use file instead stdin', type=argparse.FileType('rb'),
    nargs="?", default=sys.stdin.buffer
)
send_parser.add_argument(
    '--stealth', help="Don't save sender or source key hashes",
    action="store_true"
)
send_parser.add_argument(
    'dest', action="store", nargs="+", help='Destination url'
)
