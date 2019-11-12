from django.http import HttpResponse, Http404, HttpResponseRedirect, HttpRequest
from django.template import loader
from django.shortcuts import get_object_or_404, render, render_to_response
from django.urls import reverse
from django.contrib import messages
from Main_engine import main_engine
from collections import OrderedDict
from .models import PE_info
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger

import json, os

from Main_engine.models import Result


def showindex(request):
    return render(request, 'Main_engine/index.html')

def recent(request):
    return render(request, 'Main_engine/index.html')

def pe(request):
    pe_list = PE_info.objects.order_by('timenum').all()

    paginator = Paginator(pe_list, 1)

    page = request.GET.get('page', 1)

    try:
        lists = paginator.get_page(page)
    except PageNotAnInteger:
        lists = paginator.page(1)
    except EmptyPage:
        lists = paginator.page(paginator.num_pages)

    return render(request, 'Main_engine/pe.html', {'lists': lists})


def cfg(request):

    with open(r"C:\malware\all_result\test.txt", 'rb') as test:
        cfg_ = json.loads(test.read())

    return render(request, 'Main_engine/cfg.html', {'cfg_': cfg_})


def call_main(request):

    if os.path.isfile(r"C:\malware\all_result\result.txt"):
        result_file = open(r"C:\malware\all_result\result.txt", 'rb').read()
        result = json.loads(result_file)
    else:
        result = main_engine.start_engine()

        with open(r"C:\malware\all_result\result.txt", 'w') as res:
            json.dump(result, res, ensure_ascii=False, indent='\t')

    pe_ = PE_info.objects.order_by('timenum').all()

    return render(request, 'Main_engine/result.html', {'result': result, 'pe_':pe_})


def upload_file_dropzone(request):
    print('in upload file dropzone')

    if request.method == 'POST':
        print('here is post')
        # if file_check(request, request.FILES['file']) is False:
        #     messages.warning(request, 'Wrong extension!')
        #     return HttpResponse('bye')
        handle_uploaded_file(request.FILES['file'])

        print(request.FILES['file'])

    return render(request, 'Main_engine/index.html')


def file_check(request,file):
    '''
    파일의 타입, 크기, 갯수를 체크해서 입장여부를 판단해주는 함수
    :param file: 업로드된 파일
    :return: T/F
    '''

    # 이름에서 확장자를 추출해 비교하는 로직
    extension = ['exe','dll','sys','idb','i64']
    file_extension = file.name.split('.')[-1]
    print(file_extension)

    file_type = file.content_type
    if file_extension in extension:
        return True
    else:

        return False
        # return render(request, 'Main_engine/index.html')

    # 파일 자체에 타입을 검사하는 로직



def handle_uploaded_file(file):
    '''
    파일을 받아서 파일의 이름으로 폴더에 저장해주는 함수
    :param file: 업로드 된 파일
    :return: None
    '''
    with open('C:\\malware\\mal_exe\\'+file.name, 'wb+') as uploaded_file:
        for chunk in file.chunks():
            uploaded_file.write(chunk)

def test(request):
    return render(request, 'Main_engine/result.html')