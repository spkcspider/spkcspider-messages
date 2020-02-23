

class HttpError(Exception):
    pass


class DestException(HttpError):
    pass


class DestSecurityException(HttpError):
    pass


class SrcException(HttpError):
    pass


class SrcSecurityException(HttpError):
    pass


class ValidationError(SrcException):
    pass


class WrongRecipient(SrcException):
    pass


class NotReady(ValidationError):
    pass


class CheckError(Exception):
    attestation = None
    errored = None
    key_list = None

    def __init__(self, *args, attestation=None, errored=None, key_list=None):
        self.attestation = attestation or None
        self.errored = errored or []
        self.key_list = key_list or []
        super().__init__(*args, *map(lambda x: x[2], self.errored))
