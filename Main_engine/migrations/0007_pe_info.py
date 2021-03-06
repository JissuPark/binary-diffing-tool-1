# Generated by Django 2.2.6 on 2019-11-08 15:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Main_engine', '0006_filter'),
    ]

    operations = [
        migrations.CreateModel(
            name='PE_info',
            fields=[
                ('filehash', models.CharField(max_length=100, primary_key=True, serialize=False)),
                ('filetype', models.TextField()),
                ('md5hash', models.TextField()),
                ('sha_1', models.TextField()),
                ('sha_256', models.TextField()),
                ('imphash', models.TextField()),
                ('ssdeephash', models.TextField()),
                ('timestamp', models.TextField()),
                ('pdbinfo', models.TextField()),
                ('file_cert', models.TextField()),
                ('cdate', models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]
