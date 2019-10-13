__all__ = ("MessageContentView",)

from django.http import Http404

from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View

from spkcspider.apps.spider.views import UserTestMixin
from spkcspider.utils.settings import get_settings_func
from spkcspider.apps.spider.models import AssignedContent

from .models import MessageContent
from .http import CbFileResponse

_empty_set = frozenset()


class MessageContentView(UserTestMixin, View):
    model = MessageContent

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        try:
            self.utoken = self.request.GET.get("utoken", "")
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
            AssignedContent.ModelDoesNotExist,
            AssignedContent.MultipleObjectsReturned
        ):
            raise Http404()

    def test_func(self):
        self.receivers = self.object.receivers.filter(
            utoken=self.utoken
        )
        return self.receivers.exists()

    def get(self, request, *args, **kwargs):
        ret = CbFileResponse(
            self.object.encrypted_content.open()
        )
        ret.msgreceivers = self.receivers
        return ret

    def options(self, request, *args, **kwargs):
        ret = super().options(request, *args, **kwargs)
        ret["Access-Control-Allow-Origin"] = "*"
        ret["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        return ret
