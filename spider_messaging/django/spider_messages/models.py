__all__ = [
    "PostBox", "WebReference", "MessageContent"
]
import json
import logging

import requests
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.files import File
from django.core.files.temp import NamedTemporaryFile
from django.db import models, transaction
from django.http import HttpResponse, HttpResponsePermanentRedirect
from django.test import Client
from django.utils.translation import pgettext
from django.views.decorators.csrf import csrf_exempt
from rdflib import XSD, Literal
from spkcspider.apps.spider import registry
from spkcspider.apps.spider.conf import get_requests_params
from spkcspider.apps.spider.models import (
    AssignedContent, AttachedFile, DataContent, ContentVariant
)
from spkcspider.constants import VariantType, spkcgraph
from spkcspider.utils.fields import add_by_field, add_property, literalize
from spkcspider.utils.urls import merge_get_url

from .http import CbFileResponse

logger = logging.getLogger(__name__)


@add_by_field(registry.contents, "_meta.model_name")
class PostBox(DataContent):
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

    class Meta:
        proxy = True

    # @classmethod
    # def feature_urls(cls, name):
    #    return [
    #        ActionUrl("fetch_message", reverse("spider_messages:message"))
    #    ]

    def map_data(self, name, field, data, graph, context):
        if name == "webreferences":
            ret = literalize(data["object"], domain_base=context["hostpart"])
            return ret
        elif name == "signatures":
            # per node create a signature Entity
            ret = literalize(data["key"], domain_base=context["hostpart"])
            value_node = add_property(
                graph, "signature", ref=ret,
                literal=literalize(
                    data["signature"], field, domain_base=context["hostpart"]
                )
            )

            graph.add((
                value_node,
                spkcgraph["hashable"],
                Literal(False)
            ))
            return ret
        return super().map_data(name, field, data, graph, context)

    @classmethod
    def localize_name(cls, name):
        _ = pgettext
        return _("content name", "Post Box")

    def get_priority(self):
        return 2

    def get_strength_link(self):
        return 11

    def get_form_kwargs(self, **kwargs):
        ret = super().get_form_kwargs(**kwargs)
        ret["scope"] = kwargs["scope"]
        ret["request"] = kwargs["request"]
        return ret

    def get_form(self, scope):
        from .forms import PostBoxForm as f
        return f

    def get_abilities(self, context):
        if context["request"].is_owner:
            return {"push_webref", "get_webref", "del_webref"}
        if (
            not self.free_data["only_persistent"] or
            context["request"].auth_token.persist >= 0
        ):
            return {"push_webref"}
        return set()

    @csrf_exempt
    def access_push_webref(self, **kwargs):
        from .forms import ReferenceForm
        if kwargs["request"].method == "GET":
            if "raw" in kwargs["request"].GET:
                return self.access_raw(**kwargs)
            return self.access_view(**kwargs)

        form = ReferenceForm(
            instance=WebReference.static_create(
                associated_kwargs={
                    "usercomponent": self.associated.usercomponent,
                    "attached_to_content": self.associated,
                    "ctype": ContentVariant.objects.get(
                        name="WebReference"
                    )
                }
            ),
            create=True,
            data=kwargs["request"].POST,
            files=kwargs["request"].FILES,
        )

        if form.is_valid():
            form.save()
            return HttpResponse(status=201)
        return HttpResponse(status=400)

    @csrf_exempt
    def access_get_webref(self, **kwargs):
        ref = self.associated.attached_contents.filter(
            id=kwargs["request"].GET.get("reference")
        ).first()
        if not ref:
            return HttpResponse(status=410)
        return ref.access_message(kwargs)

    @csrf_exempt
    def access_del_webref(self, **kwargs):
        ret = self.associated.attached_contents.filter(
            id__in=kwargs["request"].POST.get("reference")
        )
        # maybe use csrftoken later
        if not ret.exists():
            return HttpResponse(status=410)
        ret.delete()
        return HttpResponse(status=200)


@add_by_field(registry.contents, "_meta.model_name")
class WebReference(DataContent):
    # note: the name: webreferences is used for displaying references
    # never lay both together as django will try to set
    # references which is not possible with the webreference format
    # not really a list; a dict

    appearances = [
        {
            "name": "WebReference",
            "ctype": (
                VariantType.unlisted + VariantType.unique
            ),
            "strength": 0
        },
    ]

    class Meta:
        proxy = True

    def update_used_space(self, size_diff):
        #
        if size_diff == 0:
            return
        f = "remote"
        with transaction.atomic():
            self.associated.usercomponent.user_info.update_with_quota(
                size_diff, f
            )
            self.associated.usercomponent.user_info.save(
                update_fields=[
                    "used_space_local", "used_space_remote"
                ]
            )

    def get_priority(self):
        return -10

    def get_info(self):
        return super().get_info(unlisted=True)

    def get_content_name(self):
        url = self.quota_data["url"].split("?", 1)[0]
        if len(url) > 30:
            url = f"{url[:30]}..."
        return "{}{}: {}?...".format(
            self.localize_name(self.associated.ctype.name),
            self.associated_id,
            url
        )

    def get_form(self, scope):
        from .forms import ReferenceForm
        return ReferenceForm

    def access_redirect(self, kwargs):
        ret = HttpResponsePermanentRedirect(
            redirect_to=self.url
        )
        # ret["X-TYPE"] = kwargs["rtype"].name
        ret["X-KEYLIST"] = json.dumps(self.key_list)

        q = models.Q()
        for i in kwargs["request"].POST.getlist("keyhash"):
            q |= models.Q(
                target__info__contains="\x1epubkeyhash=%s" %
                i
            )
        self.associated.smarttags.filter(
            kwargs["request"].POST.getlist("keyhash")
        ).update(name="received")
        # remove completed
        AssignedContent.objects.filter(
            ctype__name="WebReference"
        ).exclude(
            smarttags__name="unread"
        ).delete()
        return ret

    def access_message(self, kwargs):
        cached_content = self.associated.attachedfiles.filter(
            name="cache"
        ).first()
        if not cached_content:
            cached_content = AttachedFile(
                content=self,
                unique=True,
                name="cache"
            )
            params, inline_domain = get_requests_params(self.url)
            fp = None
            if inline_domain:
                try:
                    resp = Client().get(
                        self.url, follow=True, secure=True, Connection="close",
                        Referer=merge_get_url(
                            "%s%s" % (
                                kwargs["hostpart"],
                                kwargs["request"].path
                            )
                        ), SERVER_NAME=inline_domain
                    )
                    if resp.status_code != 200:

                        logging.info(
                            "file retrieval failed: \"%s\" failed",
                            self.url
                        )
                        return HttpResponse("other error", status=502)

                    c_length = resp.get("content-length", None)
                    max_length = getattr(
                        settings, "SPIDER_MAX_FILE_SIZE", None
                    )
                    if (
                        max_length and (
                            c_length is None or
                            c_length > max_length
                        )
                    ):
                        return HttpResponse(
                            "Too big/not specified", status=413
                        )
                    written_size = 0
                    for chunk in resp:
                        written_size += fp.write(chunk)
                    self.update_used_space(written_size)
                    # saves object
                    cached_content.file.save("", File(fp))
                except ValidationError as exc:
                    del fp
                    logging.info(
                        "Quota exceeded", exc_info=exc
                    )
                    return HttpResponse("Quota", status=413)
            else:
                try:
                    with requests.get(
                        self.url,
                        headers={
                            "Referer": merge_get_url(
                                "%s%s" % (
                                    kwargs["hostpart"],
                                    kwargs["request"].path
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
                        fp = NamedTemporaryFile(
                            suffix='.upload',
                            dir=settings.FILE_UPLOAD_TEMP_DIR
                        )
                        written_size = 0
                        for chunk in resp.iter_content(
                            fp.DEFAULT_CHUNK_SIZE
                        ):
                            written_size += fp.write(chunk)
                        self.update_used_space(written_size)
                        # saves object
                        cached_content.file.save("", File(fp))

                except requests.exceptions.SSLError as exc:
                    logger.info(
                        "referrer: \"%s\" has a broken ssl configuration",
                        self.url, exc_info=exc
                    )
                    return HttpResponse("ssl error", status=502)
                except ValidationError as exc:
                    del fp
                    logging.info(
                        "Quota exceeded", exc_info=exc
                    )
                    return HttpResponse("Quota", status=413)
                except Exception as exc:
                    del fp
                    logging.info(
                        "file retrieval failed: \"%s\" failed",
                        self.url, exc_info=exc
                    )
                    return HttpResponse("other error", status=502)

        ret = CbFileResponse(
            cached_content.file.open("rb")
        )

        q = models.Q()
        for i in kwargs["request"].POST.getlist("keyhash"):
            q |= models.Q(
                target__info__contains="\x1epubkeyhash=%s" %
                i
            )
        ret.refcopies = self.associated.smarttags.filter(
            q
        )
        # ret["X-TYPE"] = kwargs["rtype"].name
        ret["X-KEYLIST"] = json.dumps(self.quota_data["key_list"])
        ret["X-KEYHASH-ALGO"] = self.free_data["hash_algorithm"]
        return ret


@add_by_field(registry.contents, "_meta.model_name")
class MessageContent(DataContent):
    expose_name = False
    expose_description = False

    appearances = [
        {
            "name": "MessageContent",
            "ctype": (
                VariantType.unlisted + VariantType.machine +
                VariantType.no_export
                # + VariantType.raw_update
            ),
            "strength": 0
        },
    ]

    class Meta:
        proxy = True

    def get_strength_link(self):
        return 11

    def get_priority(self):
        return -10

    def get_info(self):
        ret = super().get_info(unlisted=True)

        return "%s%s\x1e" % (
            ret, "\x1ehash=".join(self.quota_data["key_list"].keys())
        )

    def get_form(self, scope):
        from .forms import MessageForm
        return MessageForm

    def get_form_kwargs(self, request, **kwargs):
        ret = super().get_form_kwargs(request=request, **kwargs)
        ret["request"] = request
        return ret

    def access_raw_update(self, **kwargs):
        pass

    def map_data(self, name, field, data, graph, context):
        if name == "encrypted_content":
            url = self.associated.get_absolute_url("download")
            url = "{}{}?{}".format(
                context["hostpart"], url, context["context"]["sanitized_GET"]
            )
            return Literal(url, datatype=XSD.anyURI)

        return super().map_data(name, field, data, graph, context)

    @csrf_exempt
    def access_download(self, **kwargs):
        ret = CbFileResponse(
            self.cached_content
        )
        ret.msgcopies = self.copies.filter(
            keyhash__in=kwargs["request"].POST.getlist("keyhash")
        )
        ret["X-KEYLIST"] = json.dumps(self.key_list)
        return ret
