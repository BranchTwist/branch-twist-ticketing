# Generated by Django 3.2.7 on 2021-09-28 08:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('uni_ticket', '0163_alter_ticketcategorywsprotocollo_protocollo_fascicolo_numero'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='organizationalstructurewsprotocollo',
            name='protocollo_email',
        ),
        migrations.RemoveField(
            model_name='organizationalstructurewsprotocollo',
            name='protocollo_uo',
        ),
        migrations.AddField(
            model_name='ticketcategorywsprotocollo',
            name='protocollo_email',
            field=models.EmailField(blank=True, help_text='Se vuoto: amministrazione@pec.unical.it', max_length=255, null=True, verbose_name='E-mail'),
        ),
        migrations.AddField(
            model_name='ticketcategorywsprotocollo',
            name='protocollo_uo',
            field=models.CharField(blank=True, default='', max_length=12, verbose_name='UO'),
        ),
    ]
