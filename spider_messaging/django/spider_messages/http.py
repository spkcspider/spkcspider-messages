__all__ = ("CbFileResponse", )


from django.http import FileResponse

from .signals import successful_transmitted


class CbFileResponse(FileResponse):

    def close(self):
        super().close()
        if self.status_code == 200:
            successful_transmitted.send(
                sender=CbFileResponse, response=self
            )
