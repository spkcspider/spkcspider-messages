from django.urls import path


from .views import MessageContentView

app_name = "spider_messages"

urlpatterns = [
    path(
        'message/',
        MessageContentView.as_view(),
        name='message'
    )
]
