# Generated by Django 2.2.6 on 2019-11-10 11:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Main_engine', '0010_auto_20191109_2201'),
    ]

    operations = [
        migrations.AddField(
            model_name='pe_info',
            name='year',
            field=models.TextField(null=True),
        ),
    ]
