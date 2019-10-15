from django.urls import path, include
from . import views
from polls import main_engine

# app이 여러개일 경우 구분짓기위해 해당앱을 나타내는 변수
# app_name = 'Main_engine'
# URL을 찾기위한 패턴 매칭 리스트
urlpatterns = [
    path('index', views.showindex),
    path('upload', views.upload_file_dropzone, name='upload'),
    path('result', views.call_main, name='result'),
]