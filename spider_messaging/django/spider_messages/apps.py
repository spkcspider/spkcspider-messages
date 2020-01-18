__all__ = ["SpiderMessagesConfig"]

from django.apps import AppConfig

from django.db.models.signals import (
    post_delete
)

from spkcspider.apps.spider.signals import update_dynamic


from .signals import (
    SuccessMessageContentCb, SuccessReferenceCb, successful_transmitted,
    UpdateKeysCb, TriggerDynamicCb
)


class SpiderMessagesConfig(AppConfig):
    name = 'spider_messaging.django.spider_messages'
    label = 'spider_messages'
    verbose_name = 'spkcspider Messages'
    spider_url_path = 'spidermessages/'

    def ready(self):
        from spkcspider.apps.spider.models import AssignedContent

        update_dynamic.connect(
            TriggerDynamicCb
        )
        post_delete.connect(
            UpdateKeysCb, sender=AssignedContent
        )
        successful_transmitted.connect(
            SuccessMessageContentCb,
        )
        successful_transmitted.connect(
            SuccessReferenceCb,
        )
