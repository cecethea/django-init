from django.contrib import admin

from {{cookiecutter.project_slug}}.apps.notification.models import (
    Notification
)

admin.site.register(Notification)
