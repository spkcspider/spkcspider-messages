__all__ = ["CleanMessageContentsCb", "CleanReferenceCb"]

from django.apps import apps
from django.dispatch import Signal

successful_transmitted = Signal(providing_args=["response"])


def CleanMessageContentsCb(sender, response):
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
        receivers__received=False, copies__received=False
    ):
        i.encrypted_content.delete(False)
        # triggers other signals and removes content cleanly
        i.associated.delete()


def CleanReferenceCb(sender, response):
    if not hasattr(response, "refcopies"):
        return
    MessageReference = apps.get_model("spider_messages", "MessageReference")
    # update as successful transmission
    response.refcopies.update(received=True)
    # remove completed
    for i in MessageReference.objects.exclude(
        copies__received=False
    ):
        i.cached_content.delete(False)
        # triggers other signals and removes content cleanly
        i.associated.delete()
