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
            print(chunk)
            uploaded_file.write(chunk)


#     result = {
#     "41A004EBB42648DCA2AFA78680FD70DFEC9DA8C5190C2CF383A7C668A1C4C38F": {
#         "49B769536224F160B6087DC866EDF6445531C6136AB76B9D5079CE622B043200": [
#             "49b769536224f160b6087dc866edf6445531c6136ab76b9d5079ce622b043200",
#             "Tue Dec  6 11:34:00 2016 UTC",
#             0.39344262295081966,
#             0.04096140825998646,
#             445,
#             0,
#             "0,0",
#             1,
#             1
#         ],
#         "52F2B6380B492C175837418285CBEFA51F1DE3187D00C01383BB5F9CA4EBE7DB": [
#             "52f2b6380b492c175837418285cbefa51f1de3187d00c01383bb5f9ca4ebe7db",
#             "Sat Sep 29 22:01:53 2018 UTC",
#             0.0,
#             0.2909817276835418,
#             0,
#             0,
#             "0,0",
#             0,
#             0
#         ]
#     },
#     "49B769536224F160B6087DC866EDF6445531C6136AB76B9D5079CE622B043200": {
#         "41A004EBB42648DCA2AFA78680FD70DFEC9DA8C5190C2CF383A7C668A1C4C38F": [
#             "41a004ebb42648dca2afa78680fd70dfec9da8c5190c2cf383a7c668a1c4c38f",
#             "Tue Dec  6 11:34:00 2016 UTC",
#             1.0,
#             0.04096140825998646,
#             445,
#             0,
#             "0,0",
#             1,
#             1
#         ],
#         "52F2B6380B492C175837418285CBEFA51F1DE3187D00C01383BB5F9CA4EBE7DB": [
#             "52f2b6380b492c175837418285cbefa51f1de3187d00c01383bb5f9ca4ebe7db",
#             "Sat Sep 29 22:01:53 2018 UTC",
#             0.0,
#             0.11184606133493687,
#             0,
#             0,
#             "0,0",
#             0,
#             0
#         ]
#     },
#     "52F2B6380B492C175837418285CBEFA51F1DE3187D00C01383BB5F9CA4EBE7DB": {
#         "41A004EBB42648DCA2AFA78680FD70DFEC9DA8C5190C2CF383A7C668A1C4C38F": [
#             "41a004ebb42648dca2afa78680fd70dfec9da8c5190c2cf383a7c668a1c4c38f",
#             "Tue Dec  6 11:34:00 2016 UTC",
#             0.0,
#             0.2909817276835418,
#             0,
#             0,
#             "0,0",
#             0,
#             0
#         ],
#         "49B769536224F160B6087DC866EDF6445531C6136AB76B9D5079CE622B043200": [
#             "49b769536224f160b6087dc866edf6445531c6136ab76b9d5079ce622b043200",
#             "Tue Dec  6 11:34:00 2016 UTC",
#             0.0,
#             0.11184606133493687,
#             0,
#             0,
#             "0,0",
#             0,
#             0
#         ]
#     }
# }