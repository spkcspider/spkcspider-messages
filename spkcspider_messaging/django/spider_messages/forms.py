__all__ = ["ReferenceForm", "PostBoxForm", "MessageForm"]

import json
from urllib.parse import urljoin


from django.db.models import Q
from django import forms
from django.urls import reverse
from django.utils.translation import gettext as _

from spkcspider_messaging.constants import ReferenceType
from spkcspider.apps.spider.conf import get_anchor_domain, get_anchor_scheme

from .models import WebReference, PostBox, MessageContent


class ReferenceForm(forms.ModelForm):
    class Meta:
        model = WebReference
        fields = ["url", "key_list", "rtype"]
    create = False

    def __init__(self, create=False, **kwargs):
        self.create = create
        super().__init__(**kwargs)

    def clean_key_list(self):
        ret = self.cleaned_data["key_list"]
        if isinstance(ret, str):
            ret = json.loads(ret)
        q = Q()
        for i in ret.keys():
            q |= ~Q(
                keys__associated_rel__info__contains="\x1epubkeyhash=%s" %
                i
            )

        if self.model.objects.filter(q):
            raise forms.ValidationError(
                _("invalid keys"),
                code="invalid_keys"
            )
        return ret

    def _save_m2m(self):
        super()._save_m2m()
        if self.create and self.instance.rtype != ReferenceType.content.value:
            for h in self.instance.key_list.keys():
                self.instance.copies.create(keyhash=h)


class PostBoxForm(forms.ModelForm):
    message_list = forms.CharField(
        widget=forms.HiddenInput()
    )
    combined_keyhash = forms.CharField()

    class Meta:
        model = PostBox
        fields = ["only_persistent", "shared", "keys"]

    def __init__(self, scope, **kwargs):
        super().__init__(**kwargs)
        if scope in {"view", "raw"}:
            self.fields["message_list"] = \
                json.dumps({
                    "messages": {
                        (
                            i.id,
                            {
                                "size": (
                                    0 if i.cached_size is None else
                                    i.cached_size
                                ),
                                "sender": i.url.split("?", 1)[0]
                            }
                        ) for i in self.messages.all()
                    }
                })
        self.fields["keys"].queryset = \
            self.fields["keys"].queryset.filter(
                info__contains="\x1epubkeyhash="
            )
        if self.instance.id:
            pass

    def clean_keys(self):
        ret = self.cleaned_data["keys"]
        if len(ret) == 0:
            raise forms.ValidationError()
        return ret


class MessageForm(forms.ModelForm):
    own_hash = forms.CharField(required=False, initial="")
    url = forms.CharField(disabled=True, initial="")

    class Meta:
        model = MessageContent
        fields = ["encrypted_content", "key_list"]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if self.instance.id:
            self.fields["url"].initial = urljoin(
                "{}://{}".format(
                    get_anchor_scheme(),
                    get_anchor_domain()
                ), reverse(
                    "spider_messages:message"
                ),
                "?"
            )
        else:
            del self.fields["url"]

    def _save_m2m(self):
        super()._save_m2m()
        #
        for h in self.instance.key_list.keys():
            self.instance.copies.create(
                keyhash=h, received=(h == self.cleaned_data["own_hash"])
            )
