__all__ = [
    "SuccessMessageContentsCb", "SuccessReferenceCb", "UpdateKeysCb"
]

from django.apps import apps
from django.db import models
from django.dispatch import Signal

successful_transmitted = Signal(providing_args=["response"])
_feature_update_actions = frozenset({"post_add", "post_remove", "post_clear"})


def SuccessMessageContentsCb(sender, response, **kwargs):
    if (
        not getattr(response, "msgreceivers", None) and
        not getattr(response, "msgcopies", None)
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
        models.Q(receivers__received=False) |
        models.Q(copies__received=False)
    ):
        # triggers other signals and removes content cleanly
        i.associated.delete()


def SuccessReferenceCb(sender, response, **kwargs):
    if not hasattr(response, "refcopies"):
        return
    WebReference = apps.get_model("spider_messages", "WebReference")
    # update as successful transmission
    response.refcopies.update(received=True)
    # remove completed
    WebReference.objects.exclude(
        copies__received=False
    ).delete()


def UpdateKeysCb(sender, instance, action, **kwargs):
    if action not in _feature_update_actions:
        return
    WebReferenceCopy = apps.get_model("spider_messages", "WebReferenceCopy")
    WebReference = apps.get_model("spider_messages", "WebReference")
    MessageCopy = apps.get_model("spider_messages", "MessageCopy")
    MessageContent = apps.get_model("spider_messages", "MessageContent")
    q = models.Q()
    for i in instance.keys.all():
        q |= models.Q(
            keyhash=i.associated.getlist("pubkeyhash", 1)[0]
        )
    WebReferenceCopy.objects.filter(
        ref__postbox=instance
    ).exclude(q).delete()
    # remove old, completed webreferences
    WebReference.objects.exclude(
        copies__received=False
    ).delete()
    MessageCopy.objects.filter(
        ref__associated_rel__attached_to_content=instance
    ).exclude(q).delete()
    # remove old, completed message contents
    MessageContent.objects.exclude(
        models.Q(copies__received=False) |
        models.Q(receivers__received=False)
    ).delete()


def DeleteFileCb(sender, instance, **kwargs):
    WebReference = apps.get_model("spider_messages", "WebReference")
    if isinstance(instance, WebReference):
        if instance.cached_size is not None:
            instance.cached_content.delete(False)
    else:
        instance.encrypted_content.delete(False)
