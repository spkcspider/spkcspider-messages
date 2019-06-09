__all__ = ("ReferenceView", "MessageContentView")

# from django.conf import settings
from django.http import Http404, JsonResponse, HttpResponse
from django.shortcuts import get_object_or_404

from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View

from spkcspider.apps.spider.views import UserTestMixin
from spkcspider.apps.spider.helpers import get_settings_func
from spkcspider.apps.spider.models import (
    AuthToken, AssignedContent
)
from .models import WebReference, MessageContent
from .http import CbFileResponse
from .forms import ReferenceForm

_empty_set = frozenset()


class ReferenceView(UserTestMixin, View):
    model = WebReference
    form_class = ReferenceForm

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        try:
            request.auth_token = get_object_or_404(
                AuthToken, token=request.GET.get("token", "")
            )
            obj = self.get_object()
            self.usercomponent = obj.usercomponent
            self.object = obj.content
            return super().dispatch(request, *args, **kwargs)
        except Http404:
            return get_settings_func(
                "SPIDER_RATELIMIT_FUNC",
                "spkcspider.apps.spider.functions.rate_limit_default"
            )(self, request)

    def get_object(self):
        try:
            return AssignedContent.objects.from_token(
                self.request.auth_token, variant="PostBox"
            )
        except AssignedContent.ModelDoesNotExist:
            raise Http404()

    def test_func(self):
        if self.object.only_persistent:
            if self.request.auth_token.persist < 0:
                return False
        return True

    def options(self, request, *args, **kwargs):
        ret = super().options()
        ret["Access-Control-Allow-Origin"] = "*"
        ret["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return ret

    def get(self):
        """ Return tokens """
        return JsonResponse(
            {
                # "hash_algorithm": settings.SPIDER_HASH_ALGORITHM.name,
                "keys": {
                    (k.associated.getlist("pubkeyhash", 1)[0], k.key)
                    for k in self.object.keys.prefetch(
                        "associated_rel"
                    ).all()
                }
            }
        )

    def post(self, request, *args, **kwargs):
        """ create new message reference """
        form = self.form_class(
            instance=WebReference(postbox=self.object),
            create=True,
            data=self.request.POST,
            files=self.request.FILES,
        )

        if form.is_valid():
            form.save()
            return HttpResponse(status=201)
        return HttpResponse(status=400)


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
            )(self, request)

    def get_object(self):
        try:
            return AssignedContent.objects.from_url(
                self.request.GET.get("url", ""), variant="MessageContent"
            )
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

    def options(self, request, *args, **kwargs):
        ret = super().options()
        ret["Access-Control-Allow-Origin"] = "*"
        ret["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        return ret

    def get(self):
        ret = CbFileResponse(
            self.object.encrypted_content.open()
        )
        ret.msgreceivers = self.receivers
        return ret
