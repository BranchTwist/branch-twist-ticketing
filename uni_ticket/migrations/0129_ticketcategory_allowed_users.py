# Generated by Django 3.0.7 on 2020-06-23 07:01

from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('uni_ticket', '0128_auto_20200618_1003'),
    ]

    operations = [
        migrations.AddField(
            model_name='ticketcategory',
            name='allowed_users',
            field=models.ManyToManyField(to=settings.AUTH_USER_MODEL),
        ),
    ]
