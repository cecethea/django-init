from django.contrib import admin

from project.apps.user.models import User, ActionToken

admin.site.register(User)
admin.site.register(ActionToken)
