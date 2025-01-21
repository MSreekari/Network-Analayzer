from django.db import models
from django.contrib.auth.models import User

class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="notifications")
    message = models.TextField()
    is_read = models.BooleanField(default=False)  # To mark notifications as read or unread
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Notification for {self.user.username} - {self.message[:30]}"
