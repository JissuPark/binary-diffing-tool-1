# Generated by Django 2.2.7 on 2019-11-12 07:06

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Main_engine', '0014_pe_info_imphash'),
    ]

    operations = [
        migrations.AddField(
            model_name='pe_info',
            name='ContainedSections',
            field=models.BigIntegerField(null=True),
        ),
        migrations.AddField(
            model_name='pe_info',
            name='EntryPoint',
            field=models.BigIntegerField(null=True),
        ),
        migrations.AddField(
            model_name='pe_info',
            name='Targetmachine',
            field=models.TextField(null=True),
        ),
    ]