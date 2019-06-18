__all__ = ["ReferenceForm", "PostBoxForm", "MessageForm"]

import re
import json
from urllib.parse import urljoin

from django.conf import settings
from django.db.models import Q
from django import forms
from django.urls import reverse
from django.utils.translation import gettext as _

from spkcspider_messaging.constants import ReferenceType
from spkcspider.apps.spider.conf import get_anchor_domain, get_anchor_scheme
from spkcspider.apps.spider.helpers import get_hashob
from spkcspider.apps.spider.fields import JsonField
from .widgets import SignatureWidget

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
        widget=forms.HiddenInput(), disabled=True
    )
    setattr(message_list, "hashable", False)
    combined_keyhash = forms.CharField(
        label=_("Key activation hash"), help_text=_(
            "Re-sign with every active key for activating new key "
            "or removing a key"
        )
    )
    setattr(combined_keyhash, "hashable", True)
    setattr(
        combined_keyhash,
        "view_form_field_template",
        "spider_messages/partials/fields/view_combined_keyhash.html"
    )
    hash_algorithm = forms.CharField(
        widget=forms.HiddenInput(), disabled=True,
        initial=settings.SPIDER_HASH_ALGORITHM.name
    )
    setattr(hash_algorithm, "hashable", False)
    signatures = JsonField(
        widget=SignatureWidget(
            item_label=_("Signature")
        )
    )
    setattr(signatures, "hashable", False)
    setattr(
        signatures,
        "view_form_field_template",
        "spider_messages/partials/fields/view_signatures.html"
    )

    extract_pupkeyhash = re.compile("\x1epubkeyhash=([^\x1e]+)")

    class Meta:
        model = PostBox
        fields = ["only_persistent", "shared", "keys"]

    def __init__(self, scope, **kwargs):
        super().__init__(**kwargs)
        if scope in {"view", "raw"}:
            self.fields["message_list"].initial = \
                json.dumps({
                    "messages": [
                        (
                            i.id,
                            {
                                "size": i.cached_size,
                                "sender": i.url.split("?", 1)[0]
                            }
                        ) for i in self.instance.references.all()
                    ]
                })
        else:
            del self.fields["message_list"]

        self.fields["keys"].queryset = \
            self.fields["keys"].queryset.filter(
                associated_rel__info__contains="\x1epubkeyhash="
            )
        if self.instance.id and self.instance.keys.exists():
            mapped_hashes = map(
                lambda x: self.extract_pupkeyhash.search(x).group(1),
                self.instance.keys.values_list(
                    "associated_rel__info", flat=True
                )
            )
            mapped_hashes = sorted(mapped_hashes)
            ho = get_hashob()
            for mh in mapped_hashes:
                ho.update(mh.encode("ascii", "ignore"))
            self.fields["combined_keyhash"].initial = ho.finalize().hex()
            self.fields["signatures"].initial = [
                {
                    "hash": x.key.associated.getlist("hash", 1)[0].split(
                        "=", 1
                    )[-1],
                    "signature": x.signature
                } for x in self.instance.key_infos.all()
            ]
        else:
            del self.fields["combined_keyhash"]
            del self.fields["signatures"]

    def clean_signatures(self):
        ret = self.cleaned_data["signatures"]
        if len(ret) == 0:
            raise forms.ValidationError()
        try:
            ret[0]["hash"] and ret[0]["signature"]
        except KeyError:
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
