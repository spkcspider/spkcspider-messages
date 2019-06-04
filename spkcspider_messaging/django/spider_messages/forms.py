__all__ = ["ReferenceForm", "PostBoxForm", "MessageForm"]

import json

from django.db.models import Q
from django import forms
from django.utils.translation import gettext as _

from spkcspider_messaging.constants import ReferenceType

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
        q = Q()
        for i in ret.keys():
            q |= Q(
                associated_rel__info__contains="\x1epubkeyhash=%s" %
                i
            )

        if self.instance.keys.exclude(q):
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
    message_list = forms.Hidden()

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


class MessageForm(forms.ModelForm):
    own_hash = forms.CharField(required=False, initial="")

    class Meta:
        model = MessageContent
        fields = ["encrypted_content", "key_list"]

    def _save_m2m(self):
        super()._save_m2m()
        #
        for h in self.instance.key_list.keys():
            self.instance.copies.create(
                keyhash=h, received=(h == self.cleaned_data["own_hash"])
            )
