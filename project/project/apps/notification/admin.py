from django.contrib import admin

from project.apps.notification.models import (
    Notification
)

admin.site.register(Notification)