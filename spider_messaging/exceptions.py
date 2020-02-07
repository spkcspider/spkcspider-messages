

class HttpError(Exception):
    pass


class DestException(HttpError):
    pass


class SrcException(HttpError):
    pass


class ValidationError(SrcException):
    pass


class WrongRecipient(SrcException):
    pass


class NotReady(ValidationError):
    pass


class CheckError(Exception):
    pass
