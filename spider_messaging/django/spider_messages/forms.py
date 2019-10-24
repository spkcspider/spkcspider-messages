__all__ = ["ReferenceForm", "PostBoxForm", "MessageForm"]

import base64
import binascii
import json
import re

from django import forms
from django.conf import settings
from django.db.models import Q
from django.urls import reverse
from django.utils.translation import gettext as _
from spider_messaging.constants import ReferenceType
from spkcspider.apps.spider.conf import get_anchor_domain, get_anchor_scheme
from spkcspider.apps.spider.fields import JsonField
from spkcspider.utils.security import get_hashob

from .models import MessageContent, PostBox, WebReference
from .widgets import EntityListWidget, SignatureWidget


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
        q = Q(pk=self.instance.postbox.pk)
        for i in ret.keys():
            q &= Q(
                keys__associated_rel__info__contains="\x1epubkeyhash=%s" %
                i
            )

        if PostBox.objects.filter(q):
            raise forms.ValidationError(
                _("invalid keys"),
                code="invalid_keys"
            )
        return ret

    def _save_m2m(self):
        super()._save_m2m()
        if self.create and self.instance.rtype != ReferenceType.content:
            for h in self.instance.key_list.keys():
                self.instance.copies.create(keyhash=h)


class PostBoxForm(forms.ModelForm):
    webreferences = JsonField(
        widget=EntityListWidget(), disabled=True
    )
    setattr(webreferences, "hashable", False)
    setattr(
        webreferences,
        "view_form_field_template",
        "spider_messages/partials/fields/view_webreferences.html"
    )
    message_objects = JsonField(
        widget=EntityListWidget(), disabled=True
    )
    setattr(message_objects, "hashable", False)
    setattr(
        message_objects,
        "view_form_field_template",
        "spider_messages/partials/fields/view_webreferences.html"
    )
    attestation = forms.CharField(
        label=_("PostBox Attestation"), help_text=_(
            "Re-sign with every active key for activating new key "
            "or removing a key"
        ), required=False,
        widget=forms.TextInput(
            attrs={
                "readonly": True,
                "style": "width:100%"
            }
        )
    )
    setattr(attestation, "hashable", True)
    setattr(
        attestation,
        "view_form_field_template",
        "spider_messages/partials/fields/view_combined_keyhash.html"
    )
    hash_algorithm = forms.CharField(
        widget=forms.HiddenInput(), disabled=True
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

    extract_pupkeyhash = re.compile("\x1epubkeyhash=([^\x1e=]+)=([^\x1e=]+)")

    class Meta:
        model = PostBox
        fields = ["only_persistent", "shared", "keys"]

    field_order = [
        "only_persistent", "shared", "keys", "attestation",
        "webreferences", "signatures"
    ]

    def __init__(self, scope, request, **kwargs):
        super().__init__(**kwargs)
        self.initial["hash_algorithm"] = settings.SPIDER_HASH_ALGORITHM.name
        if scope in {"view", "raw", "list"} and request.is_owner:
            self.initial["webreferences"] = [
                {
                    "id": i.id,
                    "size": i.cached_size,
                    "sender": "%s?..." % i.url.split("?", 1)[0]
                } for i in self.instance.references.all()
            ]
        elif scope == "export":
            self.initial["webreferences"] = [
                {
                    "key_list": i.key_list,
                    "rtype": i.rtype,
                    "url": i.url
                } for i in self.instance.references.all()
            ]
        else:
            del self.fields["webreferences"]

        if scope in {"add", "update", "export"}:
            # list valid connected key objects (pubkeyhash=)
            self.fields["keys"].queryset = \
                self.fields["keys"].queryset.filter(
                    associated_rel__info__contains="\x1epubkeyhash="
                )
        else:
            del self.fields["keys"]
        if self.instance.id and self.instance.keys.exists():
            mapped_hashes = map(
                lambda x: self.extract_pupkeyhash.search(x).group(2),
                self.instance.keys.values_list(
                    "associated_rel__info", flat=True
                )
            )
            mapped_hashes = sorted(mapped_hashes)
            hasher = get_hashob()
            for mh in mapped_hashes:
                hasher.update(binascii.unhexlify(mh))
            hasher = hasher.finalize()
            self.initial["attestation"] = \
                base64.urlsafe_b64encode(hasher).decode("ascii")
            self.initial["signatures"] = [
                {
                    "key": x.key,
                    "hash": x.key.associated.getlist("hash", 1)[0].split(
                        "=", 1
                    )[-1],
                    "signature": x.signature
                } for x in self.instance.key_infos.all()
            ]
        else:
            del self.fields["attestation"]
            del self.fields["signatures"]

    def clean_signatures(self):
        ret = self.cleaned_data["signatures"]
        if len(ret) == 0:
            raise forms.ValidationError(
                _("Requires keys")
            )
        try:
            for i in ret:
                i["hash"] and i["signature"]
        except KeyError:
            raise forms.ValidationError(
                _("invalid signature format")
            )
        return ret

    def _save_m2m(self):
        super()._save_m2m()
        for sig in self.cleaned_data.get("signatures", []):
            signature = sig.get("signature")
            if signature:
                self.instance.key_infos.filter(
                    key__associated_rel__info__contains="\x1ehash=%s=%s" %
                    (settings.SPIDER_HASH_ALGORITHM.name, sig["hash"])
                ).update(signature=signature)


class MessageForm(forms.ModelForm):
    own_hash = forms.CharField(required=False, initial="")
    fetch_url = forms.CharField(disabled=True, initial="")
    was_retrieved = forms.BooleanField(disabled=True, initial=False)
    has_changed = forms.BooleanField(disabled=True, initial=False)
    first_run = False

    class Meta:
        model = MessageContent
        fields = ["encrypted_content", "key_list"]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if self.instance.id:
            self.initial["fetch_url"] = \
                "{}://{}{}?urlpart={}/view".format(
                    get_anchor_scheme(),
                    get_anchor_domain(),
                    reverse(
                        "spider_messages:message"
                    ),
                    self.instance.associated.token
                )
            self.initial["was_retrieved"] = \
                self.instance.receivers.filter(
                    received=True
                ).exists()
            self.fields["key_list"].disabled = True
            self.fields["key_list"]
            self.first_run = False
        else:
            del self.fields["fetch_url"]
            del self.fields["was_retrieved"]
            del self.fields["has_changed"]
            self.initial["was_retrieved"] = False
            self.first_run = True

    def _save_m2m(self):
        super()._save_m2m()
        changed_data = self.changed_data
        # create or update keys
        if (
            "key_list" in changed_data or "encrypted_content" in changed_data
        ):
            for h in self.instance.key_list.keys():
                self.instance.copies.update_or_create(
                    defaults={
                        "received": (h == self.cleaned_data["own_hash"])
                    }, keyhash=h
                )
        # don't allow new tokens after the first run
        if self.first_run:
            for utoken in self.data.getlist("utokens"):
                self.instance.receivers.update_or_create(
                    utoken=utoken
                )

    def clean(self):
        super().clean()
        if self.first_run:
            postbox = \
                self.instance.associated.usercomponent.contents.filter(
                    ctype__name="PostBox"
                ).first()
            if postbox:
                self.instance.associated.attached_to_content = postbox
            else:
                self.add_error(None, forms.ValidationError(
                    _("This usercomponent has no Postbox")
                ))
        return self.cleaned_data

    def is_valid(self):
        # cannot update retrieved message
        if (
            self.initial["was_retrieved"] and
            "encrypted_content" in self.changed_data
        ):
            return False

        return super().is_valid()
