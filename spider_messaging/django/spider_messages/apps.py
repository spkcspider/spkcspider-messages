__all__ = ["SpiderMessagesConfig"]

from django.apps import AppConfig
from django.db.models.signals import m2m_changed, post_delete

from .signals import (
    DeleteFileCb, SuccessMessageContentsCb, SuccessReferenceCb, UpdateKeysCb,
    successful_transmitted
)


class SpiderMessagesConfig(AppConfig):
    name = 'spider_messaging.django.spider_messages'
    label = 'spider_messages'
    verbose_name = 'spkcspider Messages'
    spider_url_path = 'spidermessages/'

    def ready(self):
        from .models import PostBox, WebReference, MessageContent

        post_delete.connect(
            DeleteFileCb, sender=WebReference
        )
        post_delete.connect(
            DeleteFileCb, sender=MessageContent
        )
        m2m_changed.connect(
            UpdateKeysCb, sender=PostBox.keys.through
        )
        successful_transmitted.connect(
            SuccessMessageContentsCb,
        )
        successful_transmitted.connect(
            SuccessReferenceCb,
        )
