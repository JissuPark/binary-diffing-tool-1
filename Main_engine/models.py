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
    sha_1 = models.TextField(null=True)
    md5 = models.TextField(null=True)
    ssdeep = models.TextField(null=True)
    timestamp = models.TextField(null=True)
    year = models.TextField(null=True)
    timenum = models.BigIntegerField(null=True,default=0)
    imphash = models.TextField(null=True)
    cdate = models.DateTimeField(auto_now_add=True)
    Targetmachine = models.TextField(null=True)
    EntryPoint = models.BigIntegerField(null=True,default=0)
    ContainedSections = models.BigIntegerField(null=True,default=0)
    pdbname = models.TextField(null=True)
    pdbguid = models.TextField(null=True)
    pdbage = models.TextField(null=True)
    pdbpath = models.TextField(null=True)


# class Login(models.Model):
#     id = models.CharField(max_length=20, primary_key=True)
#     password = models.CharField(max_length=20)
#     register_date = models.DateTimeField(auto_now_add=True)
#
#     def __str__(self):
#         return self.username
