__all__ = ("MessageContentView",)

from django.http import Http404
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from spkcspider.apps.spider.models import AssignedContent, AuthToken
from spkcspider.apps.spider.views import UserTestMixin
from spkcspider.utils.settings import get_settings_func

from .http import CbFileResponse
from .models import MessageContent

_empty_set = frozenset()


class MessageContentView(UserTestMixin, View):
    model = MessageContent
    token = None

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
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
            return AssignedContent.objects.get(
                attachedtokens__in=self.receivers,
                ctype__name="MessageContent"
            )
        except (
            AssignedContent.DoesNotExist,
            AssignedContent.MultipleObjectsReturned
        ):
            raise Http404()

    def test_func(self):
        self.receivers = AuthToken.objects.filter(
            token__in=self.request.GET.getlist("token")
        )
        return self.receivers.exists()

    def get(self, request, *args, **kwargs):
        ret = CbFileResponse(
            self.object.encrypted_content.open()
        )
        # cached, needs only content-length
        # don't add key-list; it is just for own keys
        # owner should access message objects via access_view
        ret["content-length"] = self.object.encrypted_content.size
        ret.msgcopies = self.object.associated.smarttags.filter(
            name="unread", target=None
        )
        ret.msgreceivers = self.receivers
        return ret

    def options(self, request, *args, **kwargs):
        ret = super().options(request, *args, **kwargs)
        ret["Access-Control-Allow-Origin"] = "*"
        ret["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        return ret
