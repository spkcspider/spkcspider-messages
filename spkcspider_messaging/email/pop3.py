
import requests
from twisted.mail import smtp
from twisted.mail import pop3
from .core import startTLSFactory


from zope.interface import implementer


@implementer(pop3.IMailbox)
class Mailbox:
    """
    A base class for mailboxes.
    """
    def listMessages(self, i=None):
        """
        Retrieve the size of a message, or, if none is specified, the size of
        each message in the mailbox.

        @type i: L{int} or L{None}
        @param i: The 0-based index of the message.

        @rtype: L{int}, sequence of L{int}, or L{Deferred <defer.Deferred>}
        @return: The number of octets in the specified message, or, if an
            index is not specified, a sequence of the number of octets for
            all messages in the mailbox or a deferred which fires with
            one of those. Any value which corresponds to a deleted message
            is set to 0.

        @raise ValueError or IndexError: When the index does not correspond to
            a message in the mailbox.  The use of ValueError is preferred.
        """
        requests
        return []

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
        raise ValueError

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

    portal = None

    def buildProtocol(self, addr):
        p = self.protocol()
        p.portal = self.portal
        p.host = self.domain
        p.timeOut = self.timeout
        return super().buildProtocol(p)
