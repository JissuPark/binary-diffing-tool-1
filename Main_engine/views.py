import timeit


from django.shortcuts import get_object_or_404, render, render_to_response
from Main_engine import main_engine
from Main_engine.Extract_Engine.PE_feature import extract_pe
from .models import PE_info
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
import json
import os


def showindex(request):
    main_engine.delete_file()
    return render(request, 'Main_engine/index.html')

def about(request):
    return render(request, 'Main_engine/about.html')

def recent(request):
    return render(request, 'Main_engine/index.html')

def pe(request):
    p_dict = extract_pe.pe_into_file()
    #print(p_dict)
    return render(request, 'Main_engine/pe.html', {'p_dict': p_dict})


def cfg(request):
    cfg_dict = dict()
    cfg_file = open(r'C:\malware\all_result\cfg\result_cfg.txt', 'rb')
    match_cfg = json.loads(cfg_file.read())
    cfg_file.close()
    for inputfile in match_cfg:
        PATH = r'C:\malware\all_result\idb'
        for file in os.listdir(PATH):
            if file.split('.')[0] == inputfile.split('.')[0]:
                file_path = os.path.join(PATH, file)
                cfg = open(file_path, 'rb')
                cfg_dict[file] = json.loads(cfg.read())
                cfg.close()
    return render(request, 'Main_engine/cfg.html', {'cfg': cfg_dict, 'matching': match_cfg})


def cg(request):
    cg_dict = dict()
    PATH = r'C:\malware\all_result\cg'
    for file in os.listdir(PATH):
        file_path = os.path.join(PATH, file)
        with open(file_path, 'rb') as cg:
            cg_dict[file] = json.loads(cg.read())

    return render(request, 'Main_engine/cg.html', {'cg': cg_dict})


def loading(request):

    default_path = "C:\\malware\\all_result\\result.txt"

    default_path2 = "C:\\malware\\all_result\\pe_r"

    if os.path.exists(default_path2):
        for file in os.scandir(default_path2):
            print(file.path)
            os.remove(file.path)
        print('Remove All File')
    else:
        print('Directory Not Found')

    if os.path.isfile(default_path):
        os.remove(default_path)

    default_path3 = "C:\\malware\\all_result\\pe_r"


    if os.path.exists(default_path3):
        for file in os.scandir(default_path3):
            print(file.path)
            os.remove(file.path)
        print('Remove All File')
    else:
        print('Directory Not Found')

    flag = file_check()

    if not flag:
        return render(request, 'Main_engine/index.html', {'message': 'directory is empty or filetype is not pe !!'})
    else:
        return render(request, 'Main_engine/loading.html', )


def call_main(request):
    start = timeit.default_timer()
    try:
        if os.path.isfile(r"C:\malware\all_result\result.txt"):  # 경로가 파일인지 아닌지 검사
            result_file = open(r"C:\malware\all_result\result.txt", 'rb')
            result = json.loads(result_file.read())
            result_file.close()
        else:
            result = main_engine.start_engine()

            with open(r"C:\malware\all_result\result.txt", 'w') as res:
                json.dump(result, res, ensure_ascii=False, indent='\t')

        h_paginator = Paginator(result, 4)

        pe_ = PE_info.objects.order_by('timenum').all()

        p_basic = dict()

        pe_result_list = os.listdir(r"C:\malware\all_result\pe_r")
        for file in pe_result_list:
            if os.path.isfile(r"C:\malware\all_result\pe_r" + "\\" + file):
                with open(r"C:\malware\all_result\pe_r" + "\\" + file, 'rb') as f:
                    result_pe = f.read()
                    pe_data = json.loads(result_pe, encoding='utf-8')
                    # print(json.dumps(pe_data, indent=4))
                    for item1, item2 in pe_data.items():
                        if item1 == 'basic prop':
                            p_basic[pe_data['file_name']] = item2


        stop = timeit.default_timer()
        print('time is ????')
        print(stop - start)
        return render(request, 'Main_engine/result.html', {'result': result, 'pe_': pe_, 'p_basic': p_basic})

    except:
        print('page error')
        return render(request, 'Main_engine/error.html')


def upload_file_dropzone(request):
    print('in upload file dropzone')

    if request.method == 'POST':
        # print('here is post')
        handle_uploaded_file(request.FILES['file'])
        # print(request.FILES['file'])

    return render(request, 'Main_engine/index.html')


def file_check():
    '''
    파일의 타입, 크기, 갯수를 체크해서 입장여부를 판단해주는 함수
    :return: T/F
    '''

    if len(os.listdir(r'C:\malware\mal_exe')) == 0:
        print('[DEBUG]directory is empty!')
        return False

    for file in os.listdir(r'C:\malware\mal_exe'):
        # 이름에서 확장자를 추출해 비교하는 로직
        extension = ['exe', 'dll', 'sys', 'idb', 'i64']
        file_extension = file.split('.')[-1]
        print(f'[DEBUG] {file} is {file_extension}')
        # 확장자가 없는 경우, 넘어감
        if file == file_extension:
            continue
        # 확장자가 리스트에 없는 경우 해당 파일을 삭제하고 false 반환
        if file_extension not in extension:
            os.remove(os.path.join(r'C:\malware\mal_exe', file))
            return False
    # # # 전부 돌았는데 false가 반환되지 않았다면 true 반환
    return True


def handle_uploaded_file(file):
    '''
    파일을 받아서 파일의 이름으로 폴더에 저장해주는 함수
    :param file: 업로드 된 파일
    :return: None
    '''

    with open('C:\\malware\\mal_exe\\' + file.name, 'wb+') as uploaded_file:
        for chunk in file.chunks():
            uploaded_file.write(chunk)
