from concurrent.futures.process import _MAX_WINDOWS_WORKERS
from django.utils import timezone
from django.db import models
from django.contrib.auth.models import User

# Create your models here.


class Password(models.Model):
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='owner')
    name = models.CharField(max_length=200)
    password = models.CharField(max_length=200)
    email = models.CharField(max_length=200)
    username = models.CharField(max_length=200)
    logo = models.CharField(max_length=300)
    authorized = models.ManyToManyField(User, related_name='coowner')
    last_change = models.DateTimeField()
    grade = models.FloatField()

    def save(self, *args, **kwargs):
        self.last_change = timezone.now()
        return super(Password, self).save(*args, **kwargs)

    def __str__(self):
        return self.name + ': ' + self.username

    class Meta:
        ordering = ["-id"]
