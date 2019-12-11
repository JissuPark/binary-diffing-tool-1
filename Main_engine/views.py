import timeit

from django.http import HttpResponse, Http404, HttpResponseRedirect, HttpRequest
from django.template import loader
from django.shortcuts import get_object_or_404, render, render_to_response
from django.urls import reverse
from django.contrib import messages
from Main_engine import main_engine
from collections import OrderedDict
from .models import PE_info
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from pprint import pprint
from django import template

import json
import os


def showindex(request):
    main_engine.delete_file()
    return render(request, 'Main_engine/index.html')

def recent(request):
    return render(request, 'Main_engine/index.html')

def pe(request):
    #f = open(r"C:\malware\all_result\pe_all.txt", 'w')
    pe_list = PE_info.objects.order_by('timenum').all()
    #print(pe_list)
    paginator = Paginator(pe_list, 1) #페이지당 1개씩의 pe_info

    page = request.GET.get('page', 1)
    p_dict = dict()
    p_filename = dict()
    p_rsrc_dict = dict()
    p_rsrc_cnt = dict()
    p_rsrc_lang = dict()
    p_dll_list = dict()
    p_rich_list = dict()
    p_stringfile = dict()
    pe_result_list = os.listdir(r"C:\malware\all_result\pe")
    for file in pe_result_list:
        if os.path.isfile(r"C:\malware\all_result\pe" + "\\" + file):
            result_pe = open(r"C:\malware\all_result\pe" + "\\" + file, 'rb')
            pe_data = json.loads(result_pe.read())
            for p, p_ in pe_data.items():
                if p == "cmp_section":
                    #print(p_)
                    p_dict[pe_data['file_name']] = p_

                elif p == 'rsrc_info':
                    p_rsrc_dict[pe_data['file_name']] = p_
                    #print(json.dumps(p_rsrc_dict, indent=4))

                elif p == "rsrc_count":
                    #print(json.dumps(p_, indent=4))
                    p_rsrc_cnt[pe_data['file_name']] = p_
                    #print(json.dumps(p_rsrc_cnt, indent=4))

                elif p == 'rsrc_lang':
                    #print(json.dumps(p_, indent=4))
                    p_rsrc_lang[pe_data['file_name']] = p_

                elif p == 'rich header':
                    p_rich_list[pe_data['file_name']] = p_

                elif p == 'Imports':
                    p_dll_list[pe_data['file_name']] = p_

                elif p == 'string file info':
                    p_stringfile[pe_data['file_name']] = p_

                elif p == 'time in num':
                    p_filename[pe_data['file_name']] = p_
    #print(p_filename)#json.dump(pe_data, f, ensure_ascii=False, indent='\t')
    p_filename = sorted(p_filename.items(), key=lambda x: x[1])
    #print(p_filename)

    # for i in range(len(p_filename)):
    #     pe_filename[p_filename[i][0]] = p_filename[i][1]

    pe_f = [0 for i in range(len(p_filename) + 1)]
    for i in range(len(p_filename)):
        pe_f[i+1] = p_filename[i]
    print(pe_f)

    try:
        lists = paginator.get_page(page)
    except PageNotAnInteger:
        lists = paginator.page(1)
    except EmptyPage:
        lists = paginator.page(paginator.num_pages)
    result_pe.close()
    #f.close()

    return render(request, 'Main_engine/pe.html', {'p_filename': p_filename,'pe_f': pe_f, 'lists': lists, 'p_dict': p_dict, 'p_rsrc': p_rsrc_dict,
                                                   'p_rsrc_cnt': p_rsrc_cnt, 'p_rsrc_lang': p_rsrc_lang,
                                                   'p_dll_list': p_dll_list, 'p_rich_list': p_rich_list, 'p_stringfileinfo': p_stringfile})

# def heuristic(request):
#      with open(r"C:\malware\all_result\result.txt", "r") as json_file:
#         json_data = json.load(json_file)
#         #
#         # for key in json_data:
#         #     for vkey in json_data[key]:
#         #         a = json_data[key][vkey][2]
#
#         return render(request, 'Main_engine/result.html', {'json_data': json_data})


def cfg(request):
    cfg_dict = dict()
    cfg_file = open(r'C:\malware\all_result\cfg\result_cfg.txt', 'rb')
    match_cfg = json.loads(cfg_file.read())
    cfg_file.close()
    for inputfile in match_cfg:
        PATH = r'C:\malware\all_result\idb'
        for file in os.listdir(PATH):
            if file.split('.')[0] == inputfile:
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

    default_path = ["C:\\malware\\all_result\\result.txt", "C:\\malware\\all_result\\pe_all.txt"]

    for path in default_path:
        if os.path.isfile(path):
            os.remove(path)

    flag = file_check()

    if not flag:
        return render(request, 'Main_engine/index.html', {'message':'directory is empty or filetype is not pe !!'})
    else:
        return render(request, 'Main_engine/loading.html')

def call_main(request):
    start = timeit.default_timer()
    if os.path.isfile(r"C:\malware\all_result\result.txt"): #경로가 파일인지 아닌지 검사
        result_file = open(r"C:\malware\all_result\result.txt", 'rb')
        result = json.loads(result_file.read())
        result_file.close()
    else:
        result = main_engine.start_engine()

        with open(r"C:\malware\all_result\result.txt", 'w') as res:
            json.dump(result, res, ensure_ascii=False, indent='\t')

    h_paginator = Paginator(result, 4)

    pe_ = PE_info.objects.order_by('timenum').all()

    stop = timeit.default_timer()
    print('time is ????')
    print(stop - start)

    return render(request, 'Main_engine/result.html', {'result': result, 'pe_': pe_})



def upload_file_dropzone(request):
    print('in upload file dropzone')

    if request.method == 'POST':
        #print('here is post')
        handle_uploaded_file(request.FILES['file'])
        #print(request.FILES['file'])


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
        extension = ['exe','dll','sys','idb','i64']
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

    with open('C:\\malware\\mal_exe\\'+file.name, 'wb+') as uploaded_file:
        for chunk in file.chunks():
            uploaded_file.write(chunk)