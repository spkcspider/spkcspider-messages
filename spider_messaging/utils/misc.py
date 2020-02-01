__all__ = ["EncryptedFile"]

import io


class EncryptedFile(io.RawIOBase):
    iterob = None
    _left = b""

    def __init__(self, fencryptor, nonce, fileob, headers="\n"):
        self.iterob = self.init_iter(fencryptor, nonce, fileob, headers)

    @staticmethod
    def init_iter(fencryptor, nonce, fileob, headers):
        yield b"%b\0" % nonce
        yield fencryptor.update(b"%b\n" % headers)
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
