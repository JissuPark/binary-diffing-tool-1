import timeit
from django.shortcuts import get_object_or_404, render, render_to_response, redirect
from Main_engine import main_engine
from Main_engine.Extract_Engine.PE_feature import extract_pe
from .models import PE_info #, Login
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
import json
import os

check_file_flag = 0
no_pe_file =""
all_file_error = 0
INPUTFILES = []


def showindex(request):
    global check_file_flag
    global no_pe_file
    global all_file_error

    all_file_error = 0
    check_file_flag = 0
    no_pe_file = ""
    main_engine.delete_file()
    return render(request, 'Main_engine/index.html')


def about(request):
    return render(request, 'Main_engine/about.html')


def recent(request):
    return render(request, 'Main_engine/index.html')


def pe(request):
    p_dict = extract_pe.pe_into_file()
    # print(p_dict)
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
        print(file[:-4])
        print(INPUTFILES)
        if file[:-4] in INPUTFILES:
            file_path = os.path.join(PATH, file)
            with open(file_path, 'rb') as cg:
                cg_dict[file] = json.loads(cg.read())

    return render(request, 'Main_engine/cg.html', {'cg': cg_dict})


def loading(request):
    global check_file_flag
    global no_pe_file
    global all_file_error

    error_count = 0
    print(request)
    file_folder = "C:\\malware\\mal_exe"
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

    flag = file_check()

    print(f"::{flag}")
    count = 0

    if os.path.exists(file_folder):
        print("file exit")
        for file in os.scandir(file_folder):
            print(file.path)
            count += 1
            flag2 = main_engine.pe2idb.pe_check(file.path)
            if flag2 is -1 or flag2 is -2:
                flag = False
                error_count += 1
                print(f"base file :: {os.path.basename(file.path)}")
                no_pe_file += os.path.basename(file.path) + ', '
                if os.path.isfile(file.path):
                    os.remove(file.path)
                check_file_flag = 1

    if count == error_count:
        all_file_error = 1

    if flag is None or all_file_error == 1:
        return render(request, 'Main_engine/index.html', {'message': 'directory is empty or all file are not pe !!'})
    elif flag is False or check_file_flag == 1:
        return render(request, 'Main_engine/loading.html', {'message': no_pe_file+' is(are) not pe !!'})
    else:
        return render(request, 'Main_engine/loading.html')



def call_main(request):
    start = timeit.default_timer()
#try:
    if os.path.isfile(r"C:\malware\all_result\result.txt"):  # 경로가 파일인지 아닌지 검사
        result_file = open(r"C:\malware\all_result\result.txt", 'rb')
        result = json.loads(result_file.read())
        result_file.close()
    else:
        main_engine.create_folder()
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

# except Exception as e:
#     print(f'[DEBUG]Page error by {e}')
#
#     return render(request, 'Main_engine/error.html')


def upload_file_dropzone(request):
    INPUTFILES.clear()
    if request.method == 'POST':
        for filekey in request.FILES:
            file = request.FILES[filekey]
            with open('C:\\malware\\mal_exe\\' + file.name, 'wb+') as uploaded_file:
                INPUTFILES.append(file.name)
                for chunk in file.chunks():
                    uploaded_file.write(chunk)

    return redirect('loading')


def file_check():
    """
    파일의 타입, 크기, 갯수를 체크해서 입장여부를 판단해주는 함수
    :return: T/F
    """

    if len(os.listdir(r'C:\malware\mal_exe')) == 0:
        print('[DEBUG]directory is empty!')
        return None

    # for file in os.listdir(r'C:\malware\mal_exe'):
    #     # 이름에서 확장자를 추출해 비교하는 로직
    #     extension = ['exe', 'dll', 'sys',' ']
    #     print("jaeho")
    #     file_extension = file.split('.')[-1]
    #     print(f'[DEBUG] {file} is {file_extension}')
    #     # 확장자가 있는 경우, 넘어감
    #     if file == file_extension:
    #         continue
    #     # 확장자가 리스트에 없는 경우 해당 파일을 삭제하고 false 반환
    #     if file_extension not in extension:
    #         print('jaeho2')
    #         os.remove(os.path.join(r'C:\malware\mal_exe', file))
    #         return False
    # # 전부 돌았는데 false가 반환되지 않았다면 true 반환
    return True


# def signup(request):
#     if request.method == "POST":
#         user_id = request.POST['ID']
#         user_pw = request.POST['PW']
#         # pw_check = request.POST['PWcheck']
#
#         user = Login(
#             id=user_id,
#             password=user_pw
#         )
#         user.save()
#
#         return render(request, "index.html")