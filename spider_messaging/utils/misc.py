__all__ = ["EncryptedFile"]

import io
import base64


class EncryptedFile(io.RawIOBase):
    iterob = None
    _left = b""

    def __init__(self, fencryptor, fileob, nonce=None, headers=None):
        self.iterob = self.init_iter(fencryptor, fileob, nonce, headers)

    @staticmethod
    def init_iter(fencryptor, fileob, nonce=None, headers=None):
        if isinstance(headers, dict):
            headers = b"\n".join(
                map(
                    lambda x: b"%b: %b" % (
                        x[0].encode("utf8") if isinstance(x[0], str) else x[0],
                        x[1].encode("utf8") if isinstance(x[0], str) else x[1]
                    )
                )
            )
        if nonce:
            yield b"%b\0" % base64.b64encode(nonce)
        if headers is not None:
            yield fencryptor.update(b"%b\n\n" % headers.strip())
        chunk = fileob.read(512)
        while chunk:
            assert isinstance(chunk, bytes)
            yield fencryptor.update(chunk)
            chunk = fileob.read(512)
        yield fencryptor.finalize()
        yield fencryptor.tag

    def read(self, size=-1):
        if size == -1:
            return b"".join(self.iterob)
        elif size < len(self._left):
            ret, self._left = self._left[:size], self._left[size:]
            return ret
        else:
            for chunk in self.iterob:
                self._left += chunk
                if len(self._left) >= size:
                    break
            ret, self._left = self._left[:size], self._left[size:]
            return ret
