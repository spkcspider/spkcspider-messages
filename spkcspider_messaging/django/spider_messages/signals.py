__all__ = ["SuccessMessageContentsCb", "SuccessReferenceCb"]

from django.apps import apps
from django.dispatch import Signal

successful_transmitted = Signal(providing_args=["response"])


def SuccessMessageContentsCb(sender, response, **kwargs):
    if (
        not hasattr(response, "msgreceivers") and
        not hasattr(response, "msgcopies")
    ):
        return
    MessageContent = apps.get_model("spider_messages", "MessageContent")
    # update as successful transmission
    if hasattr(response, "msgreceivers"):
        response.msgreceivers.update(received=True)
    if hasattr(response, "msgcopies"):
        response.msgcopies.update(received=True)
    # remove completed
    for i in MessageContent.objects.exclude(
        receivers__received=False
    ).exclude(copies__received=False):
        # triggers other signals and removes content cleanly
        i.associated.delete()


def SuccessReferenceCb(sender, response, **kwargs):
    if not hasattr(response, "refcopies"):
        return
    WebReference = apps.get_model("spider_messages", "WebReference")
    # update as successful transmission
    response.refcopies.update(received=True)
    # remove completed
    for i in WebReference.objects.exclude(
        copies__received=False
    ):
        # triggers other signals and removes content cleanly
        i.associated.delete()


def DeleteFileCb(sender, instance, **kwargs):
    WebReference = apps.get_model("spider_messages", "WebReference")
    if isinstance(sender, WebReference):
        if instance.cached_size is not None:
            instance.cached_content.delete(False)
    else:
        instance.encrypted_content.delete(False)
