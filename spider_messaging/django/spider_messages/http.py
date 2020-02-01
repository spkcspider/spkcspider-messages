__all__ = ("CbFileResponse", "CbHttpResponse")


from django.http import FileResponse, HttpResponse

from .signals import successful_transmitted


class CbHttpResponse(HttpResponse):
    def close(self):
        super().close()
        successful_transmitted.send(
            sender=CbHttpResponse, response=self
        )


class CbFileResponse(FileResponse):

    def close(self):
        super().close()
        successful_transmitted.send(
            sender=CbFileResponse, response=self
        )
