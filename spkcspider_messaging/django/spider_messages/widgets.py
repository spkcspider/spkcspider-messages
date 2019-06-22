__all__ = ["SignatureWidget", "MessageListWidget"]

import json

from django.forms import widgets
from django.conf import settings
from django.utils.translation import gettext_lazy as _


_extra = '' if settings.DEBUG else '.min'


class SignatureWidget(widgets.Textarea):
    template_name = 'spider_base/forms/widgets/wrapped_textarea.html'
    # for view form
    allow_multiple_selected = True

    class Media:
        js = [
            'node_modules/@json-editor/json-editor/dist/jsoneditor%s.js' % _extra,  # noqa:E501,
            'spider_messages/SignatureWidget.js'
        ]

    def __init__(
        self, *, attrs=None, wrapper_attrs=None, item_label=_("Item"), **kwargs
    ):
        if not attrs:
            attrs = {"class": ""}
        if not wrapper_attrs:
            wrapper_attrs = {}
        attrs.setdefault("class", "")
        attrs["class"] += " SignatureEditorTarget"
        # don't access them as they are lazy evaluated
        attrs["item_label"] = item_label
        self.wrapper_attrs = wrapper_attrs.copy()
        super().__init__(attrs=attrs, **kwargs)

    def __deepcopy__(self, memo):
        obj = super().__deepcopy__(memo)
        obj.wrapper_attrs = self.wrapper_attrs.copy()
        return obj

    def get_context(self, name, value, attrs):
        context = super().get_context(name, value, attrs)
        context['widget']['wrapper_attrs'] = self.wrapper_attrs
        context['widget']['wrapper_attrs']["id"] = "{}_inner_wrapper".format(
            context['widget']['attrs']["id"]
        )
        return context

    def format_value(self, value):
        if not value:
            return "[]"
        if isinstance(value, (tuple, list)):
            value = json.dumps(value)
        return str(value)

    def render(self, name, value, attrs=None, renderer=None):
        if value is None:
            value = ""
        if not isinstance(value, str):
            value = json.dumps(value, ensure_ascii=False, indent=2)

        return super().render(name, value, attrs, renderer)


class MessageListWidget(widgets.Widget):
    template_name = "spider_messages/forms/widgets/message_list_widget.html"
    input_type = None

    def format_value(self, value):
        return value
