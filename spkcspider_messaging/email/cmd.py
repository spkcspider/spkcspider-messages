__all__ = ["parser", "LambdaAction"]

import argparse
import socket


class LambdaAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if self.const is not None:
            values = self.const
        if callable(values):
            values = values(namespace)
        setattr(namespace, self.dest, values)


parser = argparse.ArgumentParser(
    help='Run email2spkcspider pipeline'
)
parser.add_argument(
    '--address', action='store', nargs=1, help="served address",
    default="127.0.0.1"
)
parser.add_argument(
    '--port', action='store', nargs=1, type=int, help='port', default=25
)
parser.add_argument(
    '-6', action=LambdaAction, help="Use ipv6", dest="family",
    const=socket.IF_INET6,
    default=lambda x: socket.IF_INET6 if ":" in x.address else socket.IF_INET,
)
parser.add_argument(
    '--no-gen', "-n", action='store_true',
    help="Don't generate private key/certificate automatically"
)
parser.add_argument(
    '--key', "-p", action='store', nargs="+", default=["key.priv"],
    help='Private Key(s)'
)
parser.add_argument(
    '--cert', action=LambdaAction, nargs=1,
    default=lambda x: "%s.pub" % x.rsplit(".", 1)[0],
    help='Certificate (used for smtp encryption)'
)
parser.add_argument(
    '--unencrypted', "-u", action=LambdaAction, help="Don't use encryption",
    const=True, default=lambda x: not hasattr(x, "cert"),
)

parser.add_argument(
    'postboxes', nargs='+',
    help='Postboxes checked for new messages'
)
