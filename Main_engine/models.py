from django.db import models
from django.utils import timezone
import datetime

'''
디비 사용을 위한 모델을 정의하는 파일
'''

class Filter(models.Model):
    filehash = models.CharField(max_length=100, primary_key=True)
    idb_filepath = models.TextField()
    pe_filepath = models.TextField(null=True)
    cdate = models.DateTimeField(auto_now_add=True)

class PE_info(models.Model):
    filename = models.CharField(max_length=100, primary_key=True)
    filesize = models.TextField()
    filetype = models.TextField()
    sha_256 = models.TextField()
    timestamp = models.TextField()
    year = models.TextField(null=True)
    timenum = models.BigIntegerField(null=True)
    cdate = models.DateTimeField(auto_now_add=True)

class Result(models.Model):
    filehash = models.CharField(max_length=100, primary_key=True)
    result_filepath = models.TextField()
    cdate = models.DateTimeField(auto_now_add=True)