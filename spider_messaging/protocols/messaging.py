

from spider_messaging.constants import SendType


class PostBox(object):
    attestation = None
    key = None
    url = None
    token = None
    client_list = None

    def __init__(self, attestation, key, url, token=None, graph=None):
        self.attestation = attestation
        self.key = key
        self.url = url
        self.update(token, graph)

    def update(self, token=None, graph=None):
        if token:
            self.token = token
        pass

    def send(self, ob, receivers, mode=SendType.shared):
        pass

    def receive(self, id, peek=False, extra_keys=None, max_size=None):
        pass

    def list(self, limit_to=None):
        pass

    def check(self, url=None, graph=None):
        if not url or url == self.url:
            pass

    def sign(self, url=None, token=None):
        pass
