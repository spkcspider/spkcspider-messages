__all__ = [
    "PostBox", "WebReference", "WebReferenceCopy", "MessageContent",
    "MessageCopy", "MessageReceiver"
]
import json
import posixpath
import logging


from django.db import models
from django.urls import reverse

from django.http import HttpResponse, HttpResponsePermanentRedirect
from django.conf import settings
from django.utils.translation import pgettext, gettext_lazy as _
from django.core.files.storage import default_storage
from django.core.files.uploadedfile import TemporaryUploadedFile
from django.core.exceptions import ValidationError
from django.test import Client


from jsonfield import JSONField

import requests

from spkcspider.apps.spider.helpers import (
    merge_get_url, get_requests_params, create_b64_token
)
from spkcspider.apps.spider.contents import BaseContent, add_content
from spkcspider.apps.spider.conf import TOKEN_SIZE
from spkcspider.apps.spider.constants import VariantType, ActionUrl

from spkcspider_messaging.constants import ReferenceType

from .http import CbFileResponse

logger = logging.getLogger(__name__)


def get_cached_content_path(instance, filename):
    ret = getattr(settings, "SPIDER_MESSAGES_DIR", "spider_messages")
    # try 100 times to find free filename
    # but should not take more than 1 try
    # IMPORTANT: strip . to prevent creation of htaccess files or similar
    for _i in range(0, 100):
        ret_path = default_storage.generate_filename(
            posixpath.join(
                ret, "cached",
                str(instance.postbox.associated.usercomponent.user.pk),
                "{}.encrypted".format(
                    create_b64_token(TOKEN_SIZE)
                )
            )
        )
        if not default_storage.exists(ret_path):
            break
    else:
        raise FileExistsError("Unlikely event: no free filename")
    return ret_path


def get_send_content_path(instance, filename):
    ret = getattr(settings, "SPIDER_MESSAGES_DIR", "spider_messages")
    # try 100 times to find free filename
    # but should not take more than 1 try
    # IMPORTANT: strip . to prevent creation of htaccess files or similar
    for _i in range(0, 100):
        ret_path = default_storage.generate_filename(
            posixpath.join(
                ret, "sending",
                str(instance.associated.usercomponent.user.pk),
                "{}.encrypted".format(
                    create_b64_token(TOKEN_SIZE)
                )
            )
        )
        if not default_storage.exists(ret_path):
            break
    else:
        raise FileExistsError("Unlikely event: no free filename")
    return ret_path


@add_content
class PostBox(BaseContent):
    expose_name = False
    expose_description = True
    appearances = [
        {
            "name": "PostBox",
            "ctype": (
                VariantType.unique + VariantType.component_feature +
                VariantType.feature_connect
            ),
            "strength": 0
        },
    ]
    only_persistent = models.BooleanField(
        default=False, blank=True, help_text=_(
            "Only allow senders with a persistent token"
        )
    )
    shared = models.BooleanField(
        default=True, blank=True, help_text=_(
            "Encrypt send messages for other clients, allow updates"
        )
    )
    keys = models.ManyToManyField(
        "spider_keys.PublicKey", related_name="+"
    )

    def map_data(self, name, field, data, graph, context):
        if name == "references":
            raise NotImplementedError()
        return super().map_data(name, field, data, graph, context)

    @classmethod
    def localize_name(cls, name):
        _ = pgettext
        return _("content name", "Post Box")

    def get_priority(self):
        return 2

    @classmethod
    def feature_urls(cls, name):
        return [
            ActionUrl("webrefpush", reverse("spider_messages:webreference"))
        ]

    def get_strength_link(self):
        return 11

    def get_form_kwargs(self, **kwargs):
        ret = super().get_form_kwargs(**kwargs)
        ret["scope"] = kwargs["scope"]
        return ret

    def get_form(self, scope):
        from .forms import PostBoxForm as f
        return f

    def access_ref(self, **kwargs):
        ref = self.references.filter(
            id=kwargs["request"].GET.get("reference")
        ).first()
        if not ref:
            return HttpResponse(status=410)
        return ref.access(kwargs)

    def get_info(self):
        return super().get_info(unlisted=True)


class WebReference(models.Model):
    id = models.BigAutoField(primary_key=True)
    url = models.URLField(max_length=600)
    rtype = models.CharField(max_length=1)
    postbox = models.ForeignKey(
        PostBox, related_name="references", on_delete=models.CASCADE
    )
    cached_content = models.FileField(
        upload_to=get_cached_content_path, blank=True
    )
    cached_size = models.PositiveIntegerField(null=True, blank=True)
    key_list = JSONField(help_text=_("encrypted keys for content"))

    def access(self, kwargs):
        """
            Use rtype for appropriate action

            special "access", don't confuse with the one of BaseContent
        """
        assert len(self.key_list) > 0
        if self.rtype == ReferenceType.message.value:
            kwargs["rtype"] = ReferenceType.message
            return self.access_message(kwargs)
        elif self.rtype == ReferenceType.redirect.value:
            kwargs["rtype"] = ReferenceType.redirect
            return self.access_redirect(kwargs)
        elif self.rtype == ReferenceType.content.value:
            kwargs["rtype"] = ReferenceType.content
            return self.access_message(kwargs)
        return HttpResponse(status=501)

    def access_redirect(self, kwargs):
        ret = HttpResponsePermanentRedirect(
            redirect_to=self.url
        )
        ret["X-TYPE"] = kwargs["rtype"].name
        ret["X-KEYLIST"] = json.dumps(self.key_list)
        self.copies.filter(
            keyhash__in=kwargs["request"].POST.getlist("keyhash")
        ).update(received=True)
        # remove completed
        for i in WebReference.objects.exclude(
            copies__received=False
        ):
            i.cached_content.delete(False)
            # triggers other signals and removes content cleanly
            i.associated.delete()
        return ret

    def access_message(self, kwargs):
        if self.cached_size is None:
            params, can_inline = get_requests_params(self.url)
            if can_inline:
                resp = Client().get(
                    self.url, follow=True, secure=True, Connection="close",
                    Referer=merge_get_url(
                        "%s%s" % (
                            kwargs["hostpart"],
                            self.request.path
                        )
                    )
                )
                if resp.status_code < 400:
                    c_length = resp.headers.get("content-length", None)
                    if (
                        c_length is None or
                        c_length > int(settings.MAX_UPLOAD_SIZE)
                    ):
                        return HttpResponse(
                            "Too big/not specified", status=413
                        )
                    fp = TemporaryUploadedFile()
                    for chunk in resp:
                        fp.write(chunk)
                    self.postbox.update_used_space(fp.size)
                    self.cached_size = fp.size
                    # saves also cached_size
                    self.cached_content.save("", fp)
            else:
                try:
                    with requests.get(
                        self.url,
                        headers={
                            "Referer": merge_get_url(
                                "%s%s" % (
                                    kwargs["hostpart"],
                                    self.request.path
                                )
                            ),
                            "Connection": "close"
                        },
                        stream=True,
                        **params
                    ) as resp:
                        resp.raise_for_status()
                        c_length = resp.headers.get("content-length", None)
                        if (
                            c_length is None or
                            c_length > int(settings.MAX_UPLOAD_SIZE)
                        ):
                            return HttpResponse("Too big", status=413)
                        fp = TemporaryUploadedFile()
                        try:
                            for chunk in resp.iter_content(
                                fp.DEFAULT_CHUNK_SIZE
                            ):
                                fp.write(chunk)
                        except Exception:
                            del fp
                            raise
                        self.postbox.update_used_space(fp.size)
                        self.cached_size = fp.size
                        # saves also cached_size
                        self.cached_content.save("", fp)

                except requests.exceptions.SSLError as exc:
                    logger.info(
                        "referrer: \"%s\" has a broken ssl configuration",
                        self.url, exc_info=exc
                    )
                    return HttpResponse("ssl error", status=502)
                except ValidationError as exc:
                    logging.info(
                        "Quota exceeded", exc_info=exc
                    )
                    return HttpResponse("Quota", status=413)
                except Exception as exc:
                    logging.info(
                        "file retrieval failed: \"%s\" failed",
                        self.url, exc_info=exc
                    )
                    return HttpResponse("other error", status=502)

        ret = CbFileResponse(
            self.cached_content.open("rb")
        )
        ret.refcopies = self.copies.filter(
            keyhash__in=kwargs["request"].POST.getlist("keyhash")
        )
        ret["X-TYPE"] = kwargs["rtype"].name
        ret["X-KEYLIST"] = json.dumps(self.key_list)
        return ret


class WebReferenceCopy(models.Model):
    id = models.BigAutoField(primary_key=True)
    ref = models.ForeignKey(
        WebReference, related_name="copies", on_delete=models.CASCADE
    )
    keyhash = models.CharField(max_length=200)
    received = models.BooleanField(default=False, blank=True)

    class Meta():
        unique_together = [
            ("ref", "keyhash")
        ]


@add_content
class MessageContent(BaseContent):
    expose_name = False
    expose_description = False
    encrypted_content = models.FileField(
        upload_to=get_send_content_path, null=True, blank=False
    )
    # required for updates
    key_list = JSONField(help_text=_("Own encrypted keys"))

    appearances = [
        {
            "name": "MessageContent",
            "ctype": (
                VariantType.unlisted + VariantType.machine +
                VariantType.no_export + VariantType.raw_update
            ),
            "strength": 0
        },
    ]

    def get_strength_link(self):
        return 11

    def access_raw_update(self, **kwargs):
        pass

    def access_view(self, **kwargs):
        ret = CbFileResponse(
            self.cached_content
        )
        if "keyhash" in kwargs["request"].POST:
            ret.msgcopies = self.copies.filter(
                keyhash__in=kwargs["request"].POST.getlist("keyhash")
            )
        ret["X-KEYLIST"] = json.dumps(self.key_list)
        return ret


class MessageCopy(models.Model):
    id = models.BigAutoField(primary_key=True)
    content = models.ForeignKey(
        MessageContent, related_name="copies", on_delete=models.CASCADE
    )
    keyhash = models.CharField(max_length=200)
    received = models.BooleanField(default=False, blank=True)

    class Meta():
        unique_together = [
            ("content", "keyhash")
        ]


class MessageReceiver(models.Model):
    id = models.BigAutoField(primary_key=True)
    content = models.ForeignKey(
        MessageContent, related_name="receivers", on_delete=models.CASCADE
    )
    received = models.BooleanField(default=False, blank=True)
    utoken = models.CharField(max_length=100)

    class Meta():
        unique_together = [
            ("content", "utoken")
        ]
