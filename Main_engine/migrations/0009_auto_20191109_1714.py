# Generated by Django 2.2.7 on 2019-11-09 08:14

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('Main_engine', '0008_result'),
    ]

    operations = [
        migrations.RenameField(
            model_name='pe_info',
            old_name='filehash',
            new_name='filename',
        ),
        migrations.RenameField(
            model_name='pe_info',
            old_name='file_cert',
            new_name='filesize',
        ),
        migrations.RemoveField(
            model_name='pe_info',
            name='pdbinfo',
        ),
    ]
