__all__ = ["ReferenceForm", "PostBoxForm", "MessageForm"]

import base64
import binascii
import json
import re

from cryptography.hazmat.primitives import hashes
from django import forms
from django.conf import settings
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
from spkcspider.constants import spkcgraph

from .widgets import SignatureWidget


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
    webreferences = ContentMultipleChoiceField(
        queryset=AssignedContent.objects.filter(
            ctype__name="WebReference"
        ), to_field_name="id", disabled=True, required=False
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

    extract_pubkeyhash = re.compile("\x1epubkeyhash=([^\x1e=]+)=([^\x1e=]+)")

    free_fields = {"only_persistent": False, "shared": True}

    def __init__(self, scope, request, **kwargs):
        super().__init__(**kwargs)
        self.initial["hash_algorithm"] = settings.SPIDER_HASH_ALGORITHM.name
        self.fields["keys"].queryset = \
            self.fields["keys"].queryset.filter(
                usercomponent=self.instance.associated.usercomponent
            )
        if scope in {"view", "raw", "list"} and request.is_owner:
            self.initial["webreferences"] = \
                self.instance.associated.attached_contents.filter(
                    ctype__name="WebReference"
                )
            self.initial["message_objects"] = \
                self.instance.associated.attached_contents.filter(
                    ctype__name="MessageContent"
                )
            keyhashes = request.POST.getlist("keyhash")
            if self.data.get("view_all", "") != "true" and keyhashes:
                self.initial["message_objects"] = \
                    self.initial["message_objects"].filter(
                        info_or(pubkeyhash=keyhashes, hash=keyhashes)
                    )
            if scope != "view":
                self.initial["webreferences"] = \
                    self.initial["webreferences"].values_list("id", flat=True)

                self.initial["message_objects"] = \
                    self.initial["message_objects"].values_list(
                        "id", flat=True
                    )
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
                lambda x: self.extract_pubkeyhash.search(x).group(2),
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
                    None: x.target,
                    "hash": x.target.getlist("hash", 1)[0],
                    "signature": x.data["signature"]
                } for x in signatures.all()
            ]
            setattr(
                self.fields["signatures"],
                "spkc_datatype",
                {
                    None: spkcgraph["Content"],
                    "hash": XSD.string,
                    "signature": XSD.string
                }
            )
        else:
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
        ret = {
            "smarttags": []
        }
        if self.instance.id:
            smarttags = self.instance.associated.smarttags.filter(
                name="key"
            )
        else:
            smarttags = SmartTag.objects.none()
        signatures = dict(
            map(
                lambda x: (x["hash"], x.get("signature") or ""),
                self.cleaned_data.get("signatures", [])
            )
        )
        for pubkey in self.cleaned_data.get("keys", []):
            smarttag = smarttags.filter(target=pubkey).first()
            if not smarttag:
                smarttag = SmartTag(
                    content=self.instance.associated,
                    unique=True,
                    name="key",
                    target=pubkey,
                    data={
                        "signature": None
                    }
                )
            if pubkey.getlist("hash", 1)[0] in signatures:
                # shown hash of key, it includes some extra information
                smarttag.data["signature"] = \
                    signatures[pubkey.getlist("hash", 1)[0]]
            elif pubkey.getlist("pubkeyhash", 1)[0] in signatures:
                # in case only the pubkeyhash is available it must be accepted
                # this is the case for automatic repair
                smarttag.data["signature"] = \
                    signatures[pubkey.getlist("pubkeyhash", 1)[0]]
            ret["smarttags"].append(smarttag)
        return ret


class ReferenceForm(DataContentForm):
    url = forms.URLField(max_length=400)
    key_list = JsonField(
        widget=forms.Textarea()
    )
    setattr(key_list, "spkc_datatype", XSD.string)

    hash_algorithm = forms.CharField(
        required=False, disabled=False
    )
    setattr(hash_algorithm, "hashable", False)

    create = False

    free_fields = {"hash_algorithm": settings.SPIDER_HASH_ALGORITHM.name}
    quota_fields = {"url": None, "key_list": dict}

    def __init__(self, create=False, **kwargs):
        self.create = create
        super().__init__(**kwargs)
        if not self.initial.get("hash_algorithm"):
            self.initial["hash_algorithm"] = \
                settings.SPIDER_HASH_ALGORITHM.name
        if not self.create:
            self.fields["hash_algorithm"].disabled = True

    def clean_hash_algorithm(self):
        ret = self.cleaned_data["hash_algorithm"]
        if ret and not hasattr(hashes, ret.upper()):
            raise forms.ValidationError(
                _("invalid hash algorithm")
            )
        return ret

    def clean_key_list(self):
        ret = self.cleaned_data["key_list"]
        for val in ret.values():
            # 256 bits = current maximum of AESGCM
            if len(val) > 32:
                raise forms.ValidationError(
                    _("key has invalid length")
                )
        return ret

    def clean(self):
        ret = super().clean()
        if (
            "hash_algorithm" in self.initial and
            not self.cleaned_data.get("hash_algorithm")
        ):
            self.cleaned_data["hash_algorithm"] = \
                self.initial["hash_algorithm"]
        q = info_or(
            pubkeyhash=list(self.cleaned_data["key_list"].keys()),
            info_fieldname="target__info"
        )

        # get from postbox key smarttags with signature
        self.cleaned_data["signatures"] = \
            self.instance.associated.attached_to_content.smarttags.filter(
                name="key"
        ).filter(q)

        # check if key_list matches with signatures;
        # otherwise MITM injection of keys are possible
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
            # update own references to add webrerence
            #   without updating PostBox
            ret["referenced_by"] = self.instance.associated.attached_to_content
            ret["smarttags"] = [
                SmartTag(
                    content=self.instance.associated,
                    unique=True,
                    name="unread",
                    target=h.target,
                    free=True
                )
                # signatures are prepared and only hold keys in key_list
                for h in self.cleaned_data["signatures"]
            ]
        return ret


class MessageForm(DataContentForm):
    own_hash = forms.CharField(
        widget=forms.HiddenInput(),
        required=False
    )
    fetch_url = forms.CharField(disabled=True, required=False, initial="")
    was_retrieved = forms.BooleanField(
        disabled=True, required=False, initial=False, help_text=_(
            "Retrieved by recipient"
        )
    )
    # by own client(s)
    received = forms.BooleanField(
        disabled=True, required=False, initial=False, help_text=_(
            "Already received by own client"
        )
    )
    key_list = JsonField(
        initial=dict, widget=forms.Textarea()
    )
    tokens = MultipleOpenChoiceField(initial=list, disabled=True)
    amount_tokens = forms.IntegerField(min_value=0, initial=1, required=False)
    encrypted_content = forms.FileField()

    hash_algorithm = forms.CharField(
        disabled=False, required=False
    )
    setattr(hash_algorithm, "hashable", False)

    first_run = False

    free_fields = {"hash_algorithm": settings.SPIDER_HASH_ALGORITHM.name}
    quota_fields = {"fetch_url": None, "key_list": dict}

    def __init__(self, request, **kwargs):
        super().__init__(**kwargs)
        if self.instance.id:
            self.fields["hash_algorithm"].disabled = True
            self.initial["tokens"] = \
                [
                    token.token
                    for token in self.instance.associated.attachedtokens.all()
            ]
            # hack around for current bad default JsonField widget
            self.initial["key_list"] = json.dumps(self.initial["key_list"])
            setattr(self.fields["key_list"], "spkc_datatype", XSD.string)

            self.initial["fetch_url"] = \
                "{}://{}{}?".format(
                    request.scheme,
                    request.get_host(),
                    reverse(
                        "spider_messages:message"
                    )
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
            keyhashes_q = info_or(
                pubkeyhash=keyhashes, hash=keyhashes,
                info_fieldname="target__info"
            )
            if keyhashes:
                self.initial["received"] = \
                    self.instance.asspciated.smarttags.filter(
                        name="received"
                    ).filter(keyhashes_q).count() == len(keyhashes)
            else:
                del self.fields["received"]
            del self.fields["amount_tokens"]
            self.first_run = False
        else:
            del self.fields["fetch_url"]
            del self.fields["was_retrieved"]
            del self.fields["received"]
            del self.fields["tokens"]

            if not self.initial.get("hash_algorithm"):
                self.initial["hash_algorithm"] = \
                    settings.SPIDER_HASH_ALGORITHM.name
            self.initial["was_retrieved"] = False
            self.first_run = True

    def clean_hash_algorithm(self):
        ret = self.cleaned_data["hash_algorithm"]
        if ret and not hasattr(hashes, ret.upper()):
            raise forms.ValidationError(
                _("invalid hash algorithm")
            )
        return ret

    def clean(self):
        super().clean()
        if (
            "hash_algorithm" in self.initial and
            not self.cleaned_data.get("hash_algorithm")
        ):
            self.cleaned_data["hash_algorithm"] = \
                self.initial["hash_algorithm"]
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

    def get_prepared_attachements(self):
        ret = {}
        changed_data = self.changed_data
        # create or update keys
        if (
            "key_list" in changed_data or "encrypted_content" in changed_data
        ):
            self.initial["received"] = False
            if self.first_run:
                keyhashes_q = info_or(
                    hash=self.cleaned_data["key_list"],
                    pubkeyhash=self.cleaned_data["key_list"]
                )
                ret["smarttags"] = [
                    SmartTag(
                        content=self.instance.associated,
                        unique=True,
                        name="unread",
                        target=t,
                        data={"hash": t.getlist("hash", 1)[0]}
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
                h1 = None
                h2 = None
                if smartkey.target:
                    h1 = smartkey.target.getlist("hash", 1)[0]
                    h2 = smartkey.target.getlist("pubkeyhash", 1)[0]
                if self.cleaned_data["own_hash"] in {h1, h2}:
                    self.initial["received"] = True
                    smartkey.name = "received"
        # don't allow new tokens after the first run
        if self.first_run:
            # update own references to add messagecontent
            #   without updating PostBox
            ret["referenced_by"] = self.instance.associated.attached_to_content
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
