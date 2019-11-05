from django.db import models
from django.utils import timezone
import datetime

'''
디비 사용을 위한 모델을 정의하는 파일
'''

class Filter(models.Model):
    filehash = models.CharField(max_length=100, primary_key=True)
    filepath = models.TextField()
    cdate = models.DateTimeField(auto_now_add=True)

    # def __str__(self):
    #     return '%s - %s' % (self.filehash, self.filepath)