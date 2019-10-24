__all__ = ("MessageContentView",)

import json

from django.http import Http404
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from spkcspider.apps.spider.models import AssignedContent
from spkcspider.apps.spider.views import UserTestMixin
from spkcspider.utils.settings import get_settings_func

from .http import CbFileResponse
from .models import MessageContent

_empty_set = frozenset()


class MessageContentView(UserTestMixin, View):
    model = MessageContent
    request = None

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        self.request = request
        try:
            obj = self.get_object()
            self.usercomponent = obj.usercomponent
            self.object = obj.content
            return super().dispatch(request, *args, **kwargs)
        except Http404:
            return get_settings_func(
                "SPIDER_RATELIMIT_FUNC",
                "spkcspider.apps.spider.functions.rate_limit_default"
            )(request, self)

    def get_object(self):
        try:
            return AssignedContent.objects.from_url_part(
                self.request.GET.get("urlpart", ""), variant="MessageContent"
            )[0]
        except (
            AssignedContent.DoesNotExist,
            AssignedContent.MultipleObjectsReturned
        ):
            raise Http404()

    def test_func(self):
        if self.request.is_owner and self.request.POST.get("own_keyhash"):
            self.copies = self.object.copies.filter(
                keyhash__in=self.request.POST.getlist("own_keyhash")
            )
            self.receivers = self.object.receivers.none()

        else:
            self.receivers = self.object.receivers.filter(
                utoken__in=self.request.GET.getlist("utoken")
            )
            self.copies = self.object.copies.none()
        return self.receivers.exists() or self.copies.exists()

    def get(self, request, *args, **kwargs):
        ret = CbFileResponse(
            self.object.encrypted_content.open()
        )
        # cached, needs only content-length
        # don't add key-list; it is just for own keys
        ret["content-length"] = self.object.encrypted_content.size
        ret.msgreceivers = self.receivers
        ret.copies = self.copies
        if ret.copies:
            ret["X-KEYLIST"] = json.dumps(self.key_list)
        return ret

    def options(self, request, *args, **kwargs):
        ret = super().options(request, *args, **kwargs)
        ret["Access-Control-Allow-Origin"] = "*"
        ret["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        return ret
