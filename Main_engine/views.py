from django.http import HttpResponse, Http404, HttpResponseRedirect, HttpRequest
from django.template import loader
from django.shortcuts import get_object_or_404, render, render_to_response
from django.urls import reverse
from django.contrib import messages
from Main_engine import main_engine
from collections import OrderedDict

import json, os

def showindex(request):
    return render(request, 'Main_engine/index.html')

def showbootstrap(request):
    return render(request, 'Main_engine/bootstrap.html')

def recent(request):
    return render(request, 'Main_engine/recent.html')

def pe(request):
    return render(request, 'Main_engine/pe.html')

def cfg(request):
    return render(request, 'Main_engine/cfg.html')

def call_main(request):

    if os.path.isfile("result.txt"):
        result = open(r"C:\malware/result/result.txt", 'rb').read()
    else:
        result_engine = main_engine.start_engine()
        result = json.dumps(result_engine, indent=4, default=str)
        with open(r"C:\malware\result\result.txt", 'w') as res:
            json.dump(result_engine, res, ensure_ascii=False, indent='\t')

    result_str = json.loads(result)

    for standard, data_s in result.items():
        print(f'[S]{standard}')
        for target, data_t in data_s.items():
            print(f'[T]{target}')
            data_time = data_t[1]
            data_bbh = data_t[2]
            data_const = data_t[3]
            data_section = data_t[4]
            data_cert = data_t[5]
            data_pdb_guid, data_pdb_path = data_t[6].split(',')
            data_imph = data_t[7]
            data_xor = data_t[8]
            print(f'[data]timestamp : {data_time}')
            print(f'[data]bbh score : {data_bbh}')
            print(f'[data]constant score : {data_const}')
            print(f'[data]section score : {data_section}')
            print(f'[data]certification : {data_cert}')
            print(f'[data]pdb_guid : {data_pdb_guid}')
            print(f'[data]pdb_path : {data_pdb_path}')
            print(f'[data]imphash : {data_imph}')
            print(f'[data]xorkey : {data_xor}')
    return render(request, 'Main_engine/result.html', {'result': result_str})


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
