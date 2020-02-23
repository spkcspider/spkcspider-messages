__all__ = [
    "SuccessMessageContentCb", "SuccessReferenceCb", "UpdateKeysCb",
    "TriggerDynamicCb"
]

from django.apps import apps
from django.db import models
from django.dispatch import Signal

successful_transmitted = Signal(providing_args=["response"])
_feature_update_actions = frozenset({"post_add", "post_remove", "post_clear"})


def SuccessMessageContentCb(sender, response, **kwargs):
    if (
        not getattr(response, "msgreceivers", None) and
        not getattr(response, "msgcopies", None)
    ):
        return
    AssignedContent = apps.get_model("spider_base", "AssignedContent")
    # update as successful transmission
    if hasattr(response, "msgreceivers"):
        response.msgreceivers.delete()
    if hasattr(response, "msgcopies"):
        response.msgcopies.update(name="received")
    # remove completed, cascading are deleted with signals
    AssignedContent.objects.filter(
        ctype__name="MessageContent"
    ).exclude(
        models.Q(attached_tokens__isnull=False) |
        models.Q(smarttags__name="unread")
    ).delete()


def SuccessReferenceCb(sender, response, **kwargs):
    if not hasattr(response, "refcopies"):
        return
    AssignedContent = apps.get_model("spider_base", "AssignedContent")
    # update as successful transmission
    response.refcopies.update(name="received")
    # remove completed, cascading are deleted with signals
    AssignedContent.objects.filter(
        ctype__name="WebReference"
    ).exclude(
        smarttags__name="unread"
    ).delete()


def UpdateKeysCb(sender, instance=None, **kwargs):
    if instance and instance.ctype.name != "PublicKey":
        return
    # remove old, completed webreferences
    sender.objects.filter(ctype__name="WebReference").exclude(
        smarttags__name="unread"
    ).delete()
    # remove old, completed message contents
    sender.objects.filter(
        ctype__name="MessageContent"
    ).exclude(
        models.Q(smarttags__name="unread") |
        models.Q(attached_tokens__isnull=False)
    ).delete()


def TriggerDynamicCb(sender, **kwargs):
    AssignedContent = apps.get_model("spider_base", "AssignedContent")
    UpdateKeysCb(AssignedContent)
