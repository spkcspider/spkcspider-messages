__all__ = ["SpiderMessagesConfig"]

from django.apps import AppConfig
from django.db.models.signals import post_delete

from .signals import (
    SuccessReferenceCb, SuccessMessageContentsCb, DeleteFileCb,
    successful_transmitted
)


class SpiderMessagesConfig(AppConfig):
    name = 'spkcspider_messaging.django.spider_messages'
    label = 'spider_messages'
    verbose_name = 'spkcspider Messages'
    spider_url_path = 'spidermessages/'

    def ready(self):
        from .models import WebReference, MessageContent

        post_delete.connect(
            DeleteFileCb, sender=WebReference
        )
        post_delete.connect(
            DeleteFileCb, sender=MessageContent
        )
        successful_transmitted.connect(
            SuccessMessageContentsCb,
        )
        successful_transmitted.connect(
            SuccessReferenceCb,
        )
