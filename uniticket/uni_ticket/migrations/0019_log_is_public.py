# Generated by Django 4.2.9 on 2024-06-04 13:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('uni_ticket', '0018_rename_log_content_type_object_id_uni_ticket__content_dbfb39_idx'),
    ]

    operations = [
        migrations.AddField(
            model_name='log',
            name='is_public',
            field=models.BooleanField(default=True),
        ),
    ]
