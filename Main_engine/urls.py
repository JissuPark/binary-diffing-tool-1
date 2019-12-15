from django.urls import path, include
from . import views
from Main_engine import main_engine

# app이 여러개일 경우 구분짓기위해 해당앱을 나타내는 변수
# app_name = 'Main_engine'
# URL을 찾기위한 패턴 매칭 리스트
urlpatterns = [
    path('', views.showindex),
    path('home', views.showindex, name='home'),
    path('upload', views.upload_file_dropzone, name='upload'), #파일 업로드 기능 구현
    path('loading', views.loading, name='loading'),
    path('result', views.call_main, name='result'),
    path('pe', views.pe, name='pe'),
    path('cfg', views.cfg, name='cfg'),
    path('cg', views.cg, name='cg'),
    path('error', views.call_main, name='error'),

]