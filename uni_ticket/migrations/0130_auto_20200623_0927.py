# Generated by Django 3.0.7 on 2020-06-23 07:27

from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('uni_ticket', '0129_ticketcategory_allowed_users'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ticketcategory',
            name='allowed_users',
            field=models.ManyToManyField(blank=True, to=settings.AUTH_USER_MODEL),
        ),
    ]
