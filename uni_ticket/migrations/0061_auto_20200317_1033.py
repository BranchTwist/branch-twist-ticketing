# Generated by Django 3.0.3 on 2020-03-17 09:33

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('uni_ticket', '0060_auto_20200317_1031'),
    ]

    operations = [
        migrations.RenameField(
            model_name='task',
            old_name='motivazione_chiusura',
            new_name='closing_reason',
        ),
        migrations.RenameField(
            model_name='ticket',
            old_name='motivazione_chiusura',
            new_name='closing_reason',
        ),
    ]
