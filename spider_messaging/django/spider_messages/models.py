__all__ = [
    "PostBox", "WebReference", "WebReferenceCopy", "MessageContent",
    "MessageCopy", "MessageReceiver"
]
from urllib.parse import urljoin
import json
import posixpath
import logging


from django.db import models

from django.http import (
    HttpResponse, HttpResponsePermanentRedirect
)
from django.conf import settings
from django.utils.translation import pgettext, gettext_lazy as _
from django.core.files.storage import default_storage
from django.core.files.temp import NamedTemporaryFile
from django.core.files import File
from django.core.exceptions import ValidationError
from django.views.decorators.csrf import csrf_exempt
from django.test import Client


from jsonfield import JSONField


from rdflib import Literal, Graph, BNode, URIRef
import requests


from spkcspider.apps.spider.serializing import (
    paginate_stream, serialize_stream
)
from spkcspider.apps.spider.queryfilters import info_or
from spkcspider.apps.spider.models import AssignedContent
from spkcspider.utils.urls import merge_get_url
from spkcspider.utils.security import create_b64_token
from spkcspider.utils.fields import add_property, literalize
from spkcspider.constants import VariantType, spkcgraph


from spkcspider.apps.spider.contents import BaseContent, add_content
from spkcspider.apps.spider.conf import TOKEN_SIZE, get_requests_params

from spider_messaging.constants import ReferenceType

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
        "spider_keys.PublicKey", related_name="+",
        through="spider_messages.PostBoxKey"
    )

    # @classmethod
    # def feature_urls(cls, name):
    #    return [
    #        ActionUrl("fetch_message", reverse("spider_messages:message"))
    #    ]

    def map_data(self, name, field, data, graph, context):
        if name == "webreferences":
            # per node create a message anonymous Node
            ret = BNode()
            for nname, val in data.items():
                value_node = add_property(
                    graph, nname, ref=ret,
                    literal=literalize(
                        val, field, domain_base=context["hostpart"]
                    )
                )

                graph.add((
                    value_node,
                    spkcgraph["hashable"],
                    Literal(False)
                ))
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

    def get_references(self):
        return self.keys.values_list("associated_rel", flat=True)

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
            not self.only_persistent or
            context["request"].auth_token.persist >= 0
        ):
            return {"push_webref"}
        return set()

    def access_get_shared(self, **kwargs):
        messages = AssignedContent.objects.filter(
            info_or(
                hash=kwargs["request"].POST.getlist("own_hash")
            ),
            attached_to_content=self,
            ctype__name="MessageContent"
        )
        session_dict = {
            "request": kwargs["request"],
            "context": kwargs,
            "scope": kwargs["scope"],
            "hostpart": kwargs["hostpart"],
            "domainauth_url": kwargs["domainauth_url"],
            "ac_namespace": spkcgraph["contents"],
            "sourceref": URIRef(urljoin(
                kwargs["hostpart"], kwargs["request"].path
            ))
        }

        g = Graph()
        g.namespace_manager.bind("spkc", spkcgraph, replace=True)

        p = paginate_stream(
            messages,
            getattr(
                settings, "SPIDER_SERIALIZED_PER_PAGE",
                settings.SPIDER_OBJECTS_PER_PAGE
            ),
            settings.SPIDER_MAX_EMBED_DEPTH
        )

        page = 1
        try:
            page = int(session_dict["request"].GET.get("page", "1"))
        except Exception:
            pass
        serialize_stream(
            g, p, session_dict,
            page=page,
            embed=False
        )
        ret = HttpResponse(
            g.serialize(format="turtle"),
            content_type="text/turtle;charset=utf-8"
        )
        # allow cors requests for raw
        ret["Access-Control-Allow-Origin"] = "*"
        return ret

    @csrf_exempt
    def access_push_webref(self, **kwargs):
        from .forms import ReferenceForm
        if kwargs["request"].method == "GET":
            if "raw" in kwargs["request"].GET:
                return self.access_raw(**kwargs)
            return self.access_view(**kwargs)
        form = ReferenceForm(
            instance=WebReference(postbox=self),
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
        ref = self.references.filter(
            id=kwargs["request"].GET.get("reference")
        ).first()
        if not ref:
            return HttpResponse(status=410)
        return ref.access(kwargs)

    @csrf_exempt
    def access_del_webref(self, **kwargs):
        ret = self.references.filter(
            id__in=kwargs["request"].POST.get("reference")
        )
        # maybe use csrftoken later
        if ret.count() == 0:
            return HttpResponse(status=410)
        ret.delete()
        return HttpResponse(status=200)

    def get_info(self):
        return super().get_info(unlisted=True)


class PostBoxKey(models.Model):
    id = models.BigAutoField(primary_key=True)
    # fix linter warning
    objects = models.Manager()
    postbox = models.ForeignKey(
        PostBox, on_delete=models.CASCADE, related_name="key_infos",
    )
    key = models.ForeignKey(
        "spider_keys.PublicKey", related_name="+", on_delete=models.CASCADE,
        editable=False
    )
    signature = models.TextField()


class WebReference(models.Model):
    id = models.BigAutoField(primary_key=True)
    url = models.URLField(max_length=600)
    rtype = models.CharField(max_length=1)
    created = models.DateTimeField(auto_now_add=True, editable=False)
    # note: the name: webreferences is used for displaying references
    # never lay both together as django will try to set
    # references which is not possible with the webreference format
    postbox = models.ForeignKey(
        PostBox, related_name="references", on_delete=models.CASCADE
    )
    cached_content = models.FileField(
        upload_to=get_cached_content_path, blank=True
    )
    cached_size = models.PositiveIntegerField(null=True, blank=True)
    # not really a list; a dict
    key_list = JSONField(help_text=_("encrypted keys for content"))

    def access(self, kwargs):
        """
            Use rtype for appropriate action

            special "access", don't confuse with the one of BaseContent
        """
        assert len(self.key_list) > 0
        if self.rtype == ReferenceType.message:
            kwargs["rtype"] = ReferenceType.message
            return self.access_message(kwargs)
        elif self.rtype == ReferenceType.redirect:
            kwargs["rtype"] = ReferenceType.redirect
            return self.access_redirect(kwargs)
        elif self.rtype == ReferenceType.content:
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
            params, inline_domain = get_requests_params(self.url)
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
                    if resp.status_code == 200:
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
                        fp = NamedTemporaryFile(
                            suffix='.upload', dir=settings.FILE_UPLOAD_TEMP_DIR
                        )
                        written_size = 0
                        for chunk in resp:
                            written_size += fp.write(chunk)
                        self.postbox.update_used_space(written_size)
                        self.cached_size = written_size
                        # updates also cached_size
                        self.cached_content.save("", File(fp))
                    else:
                        logging.info(
                            "file retrieval failed: \"%s\" failed",
                            self.url
                        )
                        return HttpResponse("other error", status=502)
                except ValidationError as exc:
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
                        try:
                            for chunk in resp.iter_content(
                                fp.DEFAULT_CHUNK_SIZE
                            ):
                                written_size += fp.write(chunk)
                        except Exception:
                            del fp
                            raise
                        self.postbox.update_used_space(written_size)
                        self.cached_size = written_size
                        # saves also cached_size
                        self.cached_content.save("", File(fp))

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
            self.refresh_from_db()

        ret = CbFileResponse(
            self.cached_content.open("rb")
        )
        if kwargs["request"].POST.get("keyhash"):
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
    key_list = JSONField(
        help_text=_("Own encrypted keys"), default=dict, blank=True
    )

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

    def get_strength_link(self):
        return 11

    def get_priority(self):
        return -10

    def get_info(self):
        ret = super().get_info(unlisted=True)

        return "%s%s\x1e" % (
            ret, "\x1ehash=".join(self.key_list.keys())
        )

    def get_form(self, scope):
        from .forms import MessageForm
        return MessageForm

    # def get_form_kwargs(self, request, **kwargs):
    #     kwargs["request"] = request
    #     return super().get_form_kwargs(request=request, **kwargs)

    def access_raw_update(self, **kwargs):
        pass

    @csrf_exempt
    def access_view(self, **kwargs):
        ret = CbFileResponse(
            self.cached_content
        )
        if kwargs["request"].POST.get("keyhash"):
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
    # cleaned up on updates via signals, see
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
