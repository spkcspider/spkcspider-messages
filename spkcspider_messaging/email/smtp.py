
from twisted.mail import smtp
from twisted.internet import defer

from zope.interface import implementer


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
class ConsoleMessageDelivery:
    def receivedHeader(self, helo, origin, recipients):
        return "Received: ConsoleMessageDelivery"

    def validateFrom(self, helo, origin):
        # All addresses are accepted
        return origin

    def validateTo(self, user):
        # Only messages directed to the "console" user are accepted.
        if user.dest.local == "console":
            return lambda: ConsoleMessage()
        raise smtp.SMTPBadRcpt(user)


class ConsoleSMTPFactory(smtp.SMTPFactory):
    protocol = smtp.ESMTP

    def __init__(self, *a, **kw):
        smtp.SMTPFactory.__init__(self, *a, **kw)
        self.delivery = ConsoleMessageDelivery()

    def buildProtocol(self, addr):
        p = smtp.SMTPFactory.buildProtocol(self, addr)
        p.delivery = self.delivery
        return p

class SmtpEndpoint(object):
    pass
