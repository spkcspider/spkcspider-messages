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
    description='Store or load message manually'
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
    '--token', default="",
    help='Optional login token, requires elsewise auth token for postbox'
)
parser.add_argument(
    'url',
    help='Postbox/Message'
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


def action_send(argv):
    try:
        aes_key, tokens, exceptions = argv.post_box.send(
            argv.file,
            receivers=argv.dest,
            headers=b"SPKC-Type: %b\n" % MessageType.file
        )
        for i in exceptions:
            logger.exception(i)
        if not exceptions:
            print("success")
    except Exception as exc:
        raise exc


def action_view(argv):
    if argv.message_id is not None:
        if argv.action == "view":
            action = AccessMethod.view
        elif argv.action == "peek":
            action = AccessMethod.peek
        elif argv.action == "bypass":
            action = AccessMethod.bypass
        else:
            raise
        try:
            argv.post_box.receive(
                argv.message_id, outfp=argv.file,
                access_method=action,
                max_size=argv.max
            )
        except Exception as exc:
            raise exc
    else:
        queried_webrefs, queried_messages = argv.post_box.list_messages()
        print("Received Messages:")
        for i in sorted(queried_webrefs.values(), key=lambda x: x["id"]):
            print(i["id"], i["name"])

        print("Own Messages:")
        for i in sorted(queried_messages.values(), key=lambda x: x["id"]):
            print(i["id"], i["name"])


def action_check(argv):
    try:
        PostBox.simple_check(
            argv.url, checker=argv.attestation, auto_add=False
        )
        print("No errors found")
    except Exception as exc:
        raise exc


def action_sign(argv):
    try:
        required, key_list = argv.post_box.sign()
        if required:
            print("Keys in chain:")
            for i in key_list:
                print("Key:", i[0].hex(), "(Public Key Hash)")
            if input("Confirm with y: ") == "y":
                argv.post_box.sign(True)
            print("Signing successful")
        else:
            print("Signature not required")
            print("Keys in chain:")
            for i in key_list:
                print("Key:", i[0].hex(), "(Public Key Hash)")
    except Exception as exc:
        raise exc


def main(argv):
    argv = parser.parse_args(argv)
    argv.attestation = AttestationChecker(argv.attestation)
    if not os.path.exists(argv.key):
        parser.exit(1, "key does not exist\n")
    match = static_token_matcher.match(argv.url)
    if not match:
        parser.exit(1, "invalid url scheme\n")
    if argv.verbose >= 2:
        logging.basicConfig(level=logging.DEBUG)
    elif argv.verbose >= 1:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.WARNING)
    access = match.groupdict()["access"]
    if (
        argv.action == "check" and
        access not in {"view", "list"}
    ):
        parser.exit(1, "url doesn't match action\n")
    if (
        argv.action in {"view", "peek"} and
        access not in {"view", "list"}
    ):
        parser.exit(1, "url doesn't match action\n")
    if argv.action == "send":
        if (
            access not in {"list", "view", "push_webref"}
        ):
            parser.exit(1, "url doesn't match action\n")

    argv.access_type = access

    with open(argv.key, "rb") as f:
        priv_key = load_priv_key(f.read())[0]

        if not priv_key:
            parser.exit(1, "invalid key: %s\n" % argv.key)

    if argv.action == "send":
        argv.post_box = PostBox(
            argv.attestation, priv_key, argv.url,
            token=argv.token
        )
        return action_send(argv)
    elif argv.action in {"view", "peek"}:
        argv.post_box = PostBox(
            argv.attestation, priv_key, argv.url,
            token=argv.token
        )
        return action_view(argv)
    elif argv.action == "check":
        return action_check(argv)
    elif argv.action == "sign":
        argv.post_box = PostBox(
            argv.attestation, priv_key, argv.url,
            token=argv.token
        )
        return action_sign(argv)


if __name__ == "__main__":
    main(sys.argv[1:])
