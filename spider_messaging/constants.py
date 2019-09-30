__all__ = ("ReferenceType", )

import enum


class ReferenceType(str, enum.Enum):
    # cause a redirect
    redirect = "a"
    # message object
    message = "b"
    # rdf file with proposed content(s)
    content = "c"

    def __str__(self):
        # output value instead of member name
        return self.value
