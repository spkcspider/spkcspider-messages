__all__ = ["ReferenceForm", "PostBoxForm", "MessageForm"]


from django import forms

from .models import WebReference, PostBox, MessageContent
from spkcspider_messaging.constants import ReferenceType


class ReferenceForm(forms.ModelForm):
    class Meta:
        model = WebReference
        fields = ["url", "key_list", "rtype"]
    create = False

    def __init__(self, create=False, **kwargs):
        self.create = create
        super().__init__(**kwargs)

    def _save_m2m(self):
        super()._save_m2m()
        if self.create and self.instance.rtype != ReferenceType.content.value:
            for h in self.instance.key_list.keys():
                self.instance.copies.create(keyhash=h)


class PostBoxForm(forms.ModelForm):
    class Meta:
        model = PostBox
        fields = ["only_persistent", "shared", "keys"]

    def __init__(self, scope, **kwargs):
        super().__init__(**kwargs)
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
