__all__ = ["parser"]

import argparse


parser = argparse.ArgumentParser(
    description='Run email2spkcspider pipeline'
)
# parser.add_argument(
#     '-6', action="store_true", help="Use ipv6", dest="family"
# )
parser.add_argument(
    '--no-gen', action='store_true',
    help="Don't generate private key/certificate automatically"
)
parser.add_argument(
    '--keysize', "-s", action='store', default=8192,
    help="Keysize for auto generated keys"
)
parser.add_argument(
    '--hash', action='store', help="Hash algorithm", default="SHA512"
)
parser.add_argument(
    '--key', action='store', nargs="+", dest="keys",
    default=["key.priv"], help='Private Key(s)'
)
parser.add_argument(
    '--cert', action="store", default=argparse.SUPPRESS,
    help='Certificate (used for smtp encryption)'
)
parser.add_argument(
    '--unencrypted', "-u", action="store_true",
    help="Allow also unencrypted pop3/smtp connections"
)

parser.add_argument(
    'postboxes', nargs='+',
    help='Postboxes checked for new messages'
)
parser.add_argument(
    '--address', "-a", action='store', help="served address",
    default="127.0.0.1"
)

parser.add_argument(
    '--smtp', action='store', type=int, help='port of smtp service',
    default=25, dest="smtp_port"
)
parser.add_argument(
    '--pop3', action='store', type=int, help='port of pop3 service',
    default=143, dest="pop3_port"
)
