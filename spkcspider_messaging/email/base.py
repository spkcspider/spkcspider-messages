
class Email2SpiderHandler:
    async def handle_DATA(self, server, session, envelope):
        peer = session.peer
        mail_from = envelope.mail_from
        rcpt_tos = envelope.rcpt_tos
        data = envelope.content         # type: bytes
        # Process message data...
        if error_occurred:
            return '500 Could not process your message'
        return '250 OK'
