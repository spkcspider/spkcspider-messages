__all__ = ["SpiderMessageConfig"]

from django.apps import AppConfig

from .signals import (
    CleanMessageContentsCb, CleanReferenceCb, successful_transmitted
)


class SpiderMessageConfig(AppConfig):
    name = 'spkcspider_messages.django.spider_messages'
    label = 'spider_messages'
    verbose_name = 'spkcspider Messages'
    spider_url_path = 'spidermessages/'

    def ready(self):

        successful_transmitted.connect(
            CleanMessageContentsCb,
        )
        successful_transmitted.connect(
            CleanReferenceCb,
        )
