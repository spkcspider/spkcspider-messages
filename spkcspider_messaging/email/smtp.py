
from twisted.mail import smtp
from twisted.internet import defer

from zope.interface import implementer

from .core import startTLSFactory


@implementer(smtp.IMessage)
class ConsoleMessage:
    def __init__(self):
        self.lines = []

    def lineReceived(self, line):
        self.lines.append(line)

    def eomReceived(self):
        print("New message received:")
        print("\n".join(self.lines))
        self.lines = None
        return defer.succeed(None)

    def connectionLost(self):
        # There was an error, throw away the stored lines
        self.lines = None


@implementer(smtp.IMessageDelivery)
class SpiderPostBoxDelivery:
    postboxes = None
    pseudo_names = {"spider", "spkcspider"}

    def __init__(self, postboxes):
        self.postboxes = set(postboxes)

    def receivedHeader(self, helo, origin, recipients):
        return "Received: ConsoleMessageDelivery"

    def validateFrom(self, helo, origin):
        if origin.domain not in self.postboxes:
            raise smtp.SMTPBadSender(origin)
        return origin

    def validateTo(self, user):
        if user.dest.local in self.pseudo_names:
            return lambda: ConsoleMessage()
        raise smtp.SMTPBadRcpt(user)


class SMTPFactory(startTLSFactory):
    domain = smtp.DNSNAME
    timeout = 600
    delivery = None
    protocol = smtp.ESMTP

    portal = None

    def buildProtocol(self, addr):
        p = self.protocol()
        p.portal = self.portal
        p.delivery = self.delivery
        p.host = self.domain
        return super().buildProtocol(p)
