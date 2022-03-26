# Generated by Django 3.1.6 on 2022-03-26 13:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("uni_ticket", "0177_auto_20220326_1157"),
    ]

    operations = [
        migrations.AlterField(
            model_name="ticketcategorywsprotocollo",
            name="protocollo_email",
            field=models.EmailField(
                blank=True,
                help_text="default: settings.PROTOCOL_EMAIL_DEFAULT",
                max_length=255,
                null=True,
                verbose_name="E-mail",
            ),
        ),
        migrations.AlterField(
            model_name="ticketcategorywsprotocollo",
            name="protocollo_uo",
            field=models.CharField(
                choices=[
                    ("2015.1", "AMMINISTRAZIONE CTC"),
                    ("2013.1", "AMMINISTRAZIONE DEMACS"),
                    ("2025.1", "AMMINISTRAZIONE DESF"),
                    ("2020.1", "AMMINISTRAZIONE DIAM"),
                    ("2014.1", "AMMINISTRAZIONE DIBEST"),
                    ("2022.1", "AMMINISTRAZIONE DICES"),
                    ("2019.1", "AMMINISTRAZIONE DIMEG"),
                    ("2017.1", "AMMINISTRAZIONE DIMES"),
                    ("2018.1", "AMMINISTRAZIONE DINCI"),
                    ("2024.1", "AMMINISTRAZIONE DISCAG"),
                    ("0", "UNIVERSITA' DELLA CALABRIA"),
                ],
                max_length=12,
                verbose_name="UO",
            ),
        ),
    ]
