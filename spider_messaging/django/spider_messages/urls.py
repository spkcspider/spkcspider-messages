from django.urls import path


from .views import ReferenceView, MessageContentView

app_name = "spider_messages"

urlpatterns = [
    path(
        'webreference/',
        ReferenceView.as_view(),
        name='webreference'
    ),
    path(
        'message/',
        MessageContentView.as_view(),
        name='message'
    )
]
