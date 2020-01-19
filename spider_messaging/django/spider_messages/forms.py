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
from rdflib import XSD
from spkcspider.apps.spider.fields import (
    ContentMultipleChoiceField, JsonField, MultipleOpenChoiceField
)
from spkcspider.apps.spider.forms.base import DataContentForm
from spkcspider.apps.spider.models import (
    AssignedContent, AttachedFile, AuthToken, SmartTag
)
from spkcspider.apps.spider.queryfilters import info_or
from spkcspider.utils.security import get_hashob

from .widgets import EntityListWidget, SignatureWidget


class ReferenceForm(DataContentForm):
    url = forms.URLField(max_length=600)
    key_list = JsonField(initial=dict)

    create = False

    def __init__(self, create=False, **kwargs):
        self.create = create
        super().__init__(**kwargs)

    def clean(self):
        ret = super().clean()
        if isinstance(self.cleaned_data["key_list"], str):
            self.cleaned_data["key_list"] = json.loads(
                self.cleaned_data["key_list"]
            )
        q = Q()
        for i in self.cleaned_data["key_list"].keys():
            q |= Q(
                target__info__regex="\x1ehash=[^=]+=%s" %
                re.escape(i)
            )
        self.cleaned_data["signatures"] = \
            self.instance.associated.attached_to_content.smarttags.filter(
                name="keys"
            ).filter(q)

        if (
            self.cleaned_data["signatures"].count() !=
            len(self.cleaned_data["key_list"])
        ):
            self.add_error("key_list", forms.ValidationError(
                _("invalid keys"),
                code="invalid_keys"
            ))
        return ret

    def get_prepared_attachements(self):
        ret = {}
        if self.create:
            ret["smarttags"] = [
                SmartTag(
                    content=self.instance.associated,
                    unique=True,
                    name="unread",
                    target=h
                )
                for h in self.cleaned_data["signatures"]
            ]
        return ret


class PostBoxForm(DataContentForm):
    only_persistent = forms.BooleanField(required=False)
    setattr(only_persistent, "hashable", False)
    shared = forms.BooleanField(required=False, initial=True)
    setattr(shared, "hashable", False)
    keys = ContentMultipleChoiceField(
        queryset=AssignedContent.objects.filter(
            ctype__name="PublicKey"
        ).filter(
            info__contains="\x1epubkeyhash="
        ), to_field_name="id",
    )
    setattr(keys, "hashable", True)
    webreferences = JsonField(
        widget=EntityListWidget(), disabled=True, required=False
    )
    setattr(webreferences, "hashable", False)
    setattr(
        webreferences,
        "view_form_field_template",
        "spider_messages/partials/fields/view_webreferences.html"
    )
    message_objects = ContentMultipleChoiceField(
        queryset=AssignedContent.objects.filter(
            ctype__name="MessageContent"
        ), to_field_name="id", disabled=True, required=False
    )
    setattr(message_objects, "hashable", False)
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
        widget=forms.HiddenInput(), disabled=True, required=False
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
    extract_hash = re.compile("\x1ehash=([^\x1e=]+)=([^\x1e=]+)")

    free_fields = {"only_persistent": False, "shared": True}

    def __init__(self, scope, request, **kwargs):
        super().__init__(**kwargs)
        self.initial["hash_algorithm"] = settings.SPIDER_HASH_ALGORITHM.name
        self.fields["keys"].queryset = \
            self.fields["keys"].queryset.filter(
                usercomponent=self.instance.associated.usercomponent
            )
        if scope in {"view", "raw", "list"} and request.is_owner:
            self.initial["webreferences"] = [
                {
                    "id": i.associated.id,
                    "size": None,
                    "sender": "%s?..." % i.quota_data["url"].split("?", 1)[0]
                } for i in self.instance.associated.attached_contents.filter(
                    ctype__name="WebReference"
                )
            ]
            self.fields["message_objects"].queryset = \
                self.fields["message_objects"].queryset.filter(
                    attached_to_content=self.instance.associated
                )
            keyhashes = request.POST.getlist("keyhash")
            if self.data.get("view_all", "") != "true" and keyhashes:
                self.fields["message_objects"].queryset = \
                    self.fields["message_objects"].queryset.filter(
                        info_or(hash=keyhashes)
                    )
        elif scope == "export":
            del self.fields["message_objects"]
        else:
            del self.fields["webreferences"]
            del self.fields["message_objects"]

        if scope not in {"add", "update", "export"}:
            del self.fields["keys"]
        if self.instance.id:
            if "keys" in self.fields:
                self.initial["keys"] = self.instance.associated.smarttags.filter(  # noqa: E501
                    name="key"
                ).values_list("target", flat=True)
            signatures = self.instance.associated.smarttags.filter(
                name="key"
            )
            mapped_hashes = map(
                lambda x: self.extract_pupkeyhash.search(x).group(2),
                signatures.values_list(
                    "target__info", flat=True
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
                    "key": x.target,
                    "hash": x.target.getlist("hash", 1)[0].split(
                        "=", 1
                    )[-1],
                    "signature": x.data["signature"]
                } for x in signatures.all()
            ]
            return
        del self.fields["attestation"]
        del self.fields["signatures"]

    def clean_signatures(self):
        ret = self.cleaned_data["signatures"]
        if len(ret) == 0:
            raise forms.ValidationError(
                _("Requires signatures")
            )
        try:
            for i in ret:
                i["hash"] and i["signature"]
        except KeyError:
            raise forms.ValidationError(
                _("invalid signature format")
            )
        return ret

    def get_prepared_attachements(self):
        key_dict = {}
        for pubkey in self.cleaned_data.get("keys", []):
            smarttag = SmartTag(
                content=self.instance.associated,
                unique=True,
                name="key",
                target=pubkey,
                data={
                    "signature": None,
                    "hash": pubkey.getlist("hash", 1)[0].split(
                        "=", 1
                    )[-1]
                }
            )
            key_dict[smarttag.data["hash"]] = smarttag

        if self.instance.id:
            keyhashes_q = Q()
            for smartkey in self.instance.associated.smarttags.filter(
                keyhashes_q, name="key"
            ):
                key_dict[smartkey.data["hash"]] = smartkey
        for sig in self.cleaned_data.get("signatures", []):
            signature = sig.get("signature")
            if signature:
                i = key_dict.get(sig["hash"])
                if i:
                    i.data["signature"] = signature
                print(key_dict)

        return {
            "smarttags": key_dict.values()
        }


class MessageForm(DataContentForm):
    own_hash = forms.CharField(required=False, initial="")
    fetch_url = forms.CharField(disabled=True, required=False, initial="")
    was_retrieved = forms.BooleanField(
        disabled=True, required=False, initial=False
    )
    key_list = JsonField(
        initial=dict, widget=forms.Textarea()
    )
    tokens = MultipleOpenChoiceField(initial=list, disabled=True)
    # by own client(s)
    received = forms.BooleanField(disabled=True, required=False, initial=False)
    amount_tokens = forms.IntegerField(min_value=0, initial=1, required=False)
    encrypted_content = forms.FileField()

    first_run = False

    quota_fields = {"fetch_url": None, "key_list": dict}

    def __init__(self, request, **kwargs):
        super().__init__(**kwargs)
        if self.instance.id:
            self.initial["tokens"] = \
                [
                    token.token
                    for token in self.instance.associated.attachedtokens.all()
            ]
            # hack around for current bad default JsonField widget
            self.initial["key_list"] = json.dumps(self.initial["key_list"])
            setattr(self.fields["key_list"], "spkc_datatype", XSD.string)

            self.initial["fetch_url"] = \
                "{}://{}{}?urlpart={}/view?".format(
                    request.scheme,
                    request.get_host(),
                    reverse(
                        "spider_messages:message"
                    ),
                    self.instance.associated.token
                )
            self.initial["encrypted_content"] = \
                self.instance.associated.attachedfiles.get(
                    name="encrypted_content"
                ).file
            setattr(
                self.fields["encrypted_content"],
                "download_url",
                self.instance.associated.get_absolute_url("download")
            )
            setattr(self.fields["encrypted_content"], "hashable", False)
            setattr(
                self.fields["encrypted_content"],
                "view_form_field_template",
                "spider_messages/partials/fields/view_encrypted_content.html"
            )
            self.initial["was_retrieved"] = \
                self.instance.associated.smarttags.filter(
                    name="received", target=None
                ).exists()
            keyhashes = self.data.getlist("keyhash")
            keyhashes_q = Q()
            for i in keyhashes:
                keyhashes_q |= Q(
                    target__info__regex="\x1ehash=[^=]+=%s" %
                    re.escape(i)
                )
            if keyhashes:
                self.initial["received"] = \
                    self.instance.asspciated.smarttags.filter(
                        name="received"
                    ).filter(keyhashes_q).count() == len(keyhashes)
            del self.fields["amount_tokens"]
            self.first_run = False
        else:
            del self.fields["fetch_url"]
            del self.fields["was_retrieved"]
            del self.fields["received"]
            del self.fields["tokens"]
            self.initial["was_retrieved"] = False
            self.first_run = True

    def get_prepared_attachements(self):
        ret = {}
        changed_data = self.changed_data
        # create or update keys
        if (
            "key_list" in changed_data or "encrypted_content" in changed_data
        ):
            self.initial["received"] = False
            if self.first_run:
                keyhashes_q = Q()
                for i in self.cleaned_data["key_list"].keys():
                    keyhashes_q |= Q(
                        info__regex="\x1ehash=[^=]+=%s" %
                        re.escape(i)
                    )
                ret["smarttags"] = [
                    SmartTag(
                        content=self.instance.associated,
                        unique=True,
                        name="unread",
                        target=t,
                        data={"hash": t.getlist("hash", 1)[0].split(
                            "=", 1
                        )[0]}
                    ) for t in self.instance.associated.usercomponent.contents.filter(  # noqa: E501
                        ctype__name="PublicKey"
                    ).filter(keyhashes_q)
                ]

                ret["smarttags"].append(
                    SmartTag(
                        content=self.instance.associated,
                        unique=True,
                        name="unread",
                        target=None
                    )
                )
            else:
                ret["smarttags"] = self.instance.associated.smarttags.all()

            for smartkey in ret["smarttags"]:
                h = None
                if smartkey.target:
                    h = smartkey.target.getlist("hash", 1)[0].split("=", 1)[-1]
                if h == self.cleaned_data["own_hash"]:
                    self.initial["received"] = True
                    smartkey.name = "received"
        # don't allow new tokens after the first run
        if self.first_run:
            ret["attachedtokens"] = [
                AuthToken(
                    persist=0,
                    usercomponent=self.instance.associated.usercomponent,
                    attached_to_content=self.instance.associated,
                    extra={
                        # don't allow anything than accessing content via
                        # view
                        "ids": []
                    }
                ) for _ in range(self.cleaned_data.get("amount_tokens", 1))
            ]
            # self.initial["tokens"] = [
            #     x.token for x in ret["attachedtokens"]
            # ]
        if "encrypted_content" in self.changed_data:
            f = None
            if self.instance.pk:
                f = self.instance.associated.attachedfiles.filter(
                    name="encrypted_content"
                ).first()
            if not f:
                f = AttachedFile(
                    unique=True, name="encrypted_content",
                    content=self.instance.associated
                )
            f.file = self.cleaned_data["encrypted_content"]
            ret["attachedfiles"] = [f]
        return ret

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
            (
                "encrypted_content" in self.changed_data or
                "key_list" in self.changed_data
            )
        ):
            return False

        return super().is_valid()
