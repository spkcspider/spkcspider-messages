import os
import sys
import asyncio

from aiosmtpd.controller import Controller

from .cmd import parser
from .base import Email2SpiderHandler


def main(argv):
    argv = parser.parse_args(argv)
    if not os.path.exists(argv.privkey[0]):
        pass
    if not all(map(os.path.exists, argv.privkey)):
        raise
    keylist = {}
    for key in argv.privkey:
        pass
    handler = Email2SpiderHandler()
    controller = Controller(handler, hostname=argv.address, port=argv.port)
    controller.start()
    input('SMTP server running. Press Return to stop server and exit.')
    controller.stop()


if __name__ == '__main__':
    main(sys.args)
