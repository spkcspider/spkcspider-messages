__all__ = ("MessageContentView",)

from django.http import Http404, HttpResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from spkcspider.apps.spider.models import AssignedContent, AuthToken
from spkcspider.apps.spider.views import UserTestMixin
from spkcspider.utils.settings import get_settings_func

from .http import CbFileResponse, CbHttpResponse
from .models import MessageContent

_empty_set = frozenset()


class MessageContentView(UserTestMixin, View):
    model = MessageContent
    token = None

    def dispatch_extra(self, request, *args, **kwargs):
        self.object = self.get_object()
        self.usercomponent = self.object.usercomponent
        return None

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        try:
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
        f = self.object.attachedfiles.get(
            name="encrypted_content"
        )
        s = request.get("X-MAX-CONTENT-LENGTH") or None
        if s is not None:
            try:
                s = int(s)
            except Exception:
                return HttpResponse(status=400)
        if s is not None and s < f.file.size:
            ret = CbHttpResponse()
        else:
            ret = CbFileResponse(
                f.file.open()
            )
            ret.msgreceivers = self.receivers

        ret.msgcopies = self.object.smarttags.filter(
            name="unread", target=None
        )
        # cached, needs only content-length
        # don't add key-list; it is just for own keys
        # owner should access message objects via access_view
        ret["content-length"] = f.file.size
        return ret

    def options(self, request, *args, **kwargs):
        ret = super().options(request, *args, **kwargs)
        ret["Access-Control-Allow-Origin"] = "*"
        ret["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        return ret
