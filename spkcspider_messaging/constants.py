__all__ = ("ReferenceType", )

import enum


class ReferenceType(str, enum.Enum):
    # cause a redirect
    redirect = "a"
    # message object
    message = "b"
    # rdf file with proposed content(s)
    content = "c"
