__all__ = ["SpiderPostbox", "POP3Factory"]

import requests
from twisted.mail import smtp
from twisted.mail import pop3
from .core import startTLSFactory


from zope.interface import implementer


@implementer(pop3.IMailbox)
class SpiderPostbox:
    postbox = None

    def __init__(self, postbox):
        self.postbox = postbox

    def _listMessages(self, i=None):
        with requests.get(self.postbox) as resp:
            ret = sorted(resp.json.items(), key=lambda x: x[0])
            ret = list(map(lambda x: x[1]["size"], ret))
            return ret

    def listMessages(self, i=None):
        return self._listMessages

    def getMessage(self, i):
        """
        Retrieve a file containing the contents of a message.

        @type i: L{int}
        @param i: The 0-based index of a message.

        @rtype: file-like object
        @return: A file containing the message.

        @raise ValueError or IndexError: When the index does not correspond to
            a message in the mailbox.  The use of ValueError is preferred.
        """
        raise ValueError

    def getUidl(self, i):
        """
        Get a unique identifier for a message.

        @type i: L{int}
        @param i: The 0-based index of a message.

        @rtype: L{bytes}
        @return: A string of printable characters uniquely identifying the
            message for all time.

        @raise ValueError or IndexError: When the index does not correspond to
            a message in the mailbox.  The use of ValueError is preferred.
        """
        return "{}?reference={}".format(
            self.postbox, i
        )
        raise ValueError

    def deleteMessage(self, i):
        """
        Mark a message for deletion.

        This must not change the number of messages in this mailbox.  Further
        requests for the size of the deleted message should return 0.  Further
        requests for the message itself may raise an exception.

        @type i: L{int}
        @param i: The 0-based index of a message.

        @raise ValueError or IndexError: When the index does not correspond to
            a message in the mailbox.  The use of ValueError is preferred.
        """
        pass

    def undeleteMessages(self):
        """
        Undelete all messages marked for deletion.

        Any message which can be undeleted should be returned to its original
        position in the message sequence and retain its original UID.
        """
        pass

    def sync(self):
        """
        Discard the contents of any message marked for deletion.
        """
        pass


class POP3Factory(startTLSFactory):
    domain = smtp.DNSNAME
    timeout = 300
    protocol = pop3.POP3
    mbox = None

    portal = None

    def buildProtocol(self, addr):
        p = self.protocol()
        p.portal = self.portal
        p.host = self.domain
        p.timeOut = self.timeout
        p.mbox = self.mbox
        return super().buildProtocol(p)
