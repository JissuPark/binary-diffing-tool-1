#coding:utf-8
import hashlib
import django
from multiprocessing import Process, Queue, Manager
import pefile
django.setup()
from Main_engine.Extract_Engine import pe2idb
from Main_engine.Extract_Engine.Flowchart_feature import extract_asm_and_const
from Main_engine.Extract_Engine.PE_feature import extract_pe
from Main_engine.Analzer_Engine import analyze_pe, analyze_flowchart
from Main_engine.Check_Packing import Packer_Detect2
from Main_engine.Unpacking import unpack_module
from Main_engine.models import *
from Main_engine.ML import new_getinfo_pe

import os
# from sklearn.externals import joblib
import json
from multiprocessing import Process, current_process, Queue, Pool



idb_file_path = "C:\\malware\\all_result\\idb\\"
pe_file_path = "C:\\malware\\all_result\\pe\\"

class Pe_Files_Check:
    '''
        * get_unique_pe_list
        -. idb로 변환할 PE 파일 중복 확인
        -. 파일명:해시값 딕셔너리에 저장 -> db or file
        -. 중복된 파일 제거
        -. Check the completely same PE file.
        -. make a dictionary of filename(key) and hashvalue(value)
        -. And then remove the same PE file.
        # exe_q에 idb로 변환할 exe파일을 쌓는다
        exe_q=Queue()
        * Return value
           dictionary of filename(key) and hashvalue(value)
        '''
    def __init__(self,pe_dir_path):
        self.pe_dir_path = pe_dir_path
        self.idat = 0
        self.idat64 = 1
        self.pe_check_error = -1
        self.pe_hash_dict = {}
        self.HEX_M_32 = 0x14c
        self.HEX_M_64 = 0x200

    def get_unique_pe_list(self):
        exe_list = os.listdir(self.pe_dir_path)

        for f in exe_list:
            f_path = os.path.join(self.pe_dir_path, f)
            fp = open(f_path, 'rb')
            f_hash = hashlib.sha256(fp.read()).hexdigest()
            fp.close()

            # file hash 중복 = 완전히 같은 파일
            # 해당 파일은 삭제(이미 diffing할 동일 파일이 존재하므로)
            if f_hash in self.pe_hash_dict.values():
                os.remove(f_path)
            else:
                pass
            self.pe_hash_dict[f_path] = f_hash


        # 이후에는 DB에 저장.
        # dictionary로 넘겨서 self.pe_hash_dict.value()의 유니크한 값들만 idb로 변환.
        # 나중에 서버에 올린 후에는 받은 파일 중 완전히 같은 파일은 서버 파일시스템에 저장하지 않는게 좋을 것 같다.
        # 예를 들어, file1, file2의 해시값이 동일한 경우
        # DB에는 file1과 file2의 파일명 그리고 해시값을 저장한다.
        # 그리고 서버 파일시스템 내에서 둘 중 하나의 파일은 지운다.
        # 일단 더 먼저 나오는 파일을 살리고 아닌 파일은 삭제하도록 하였다. 어차피 동일 파일이니깐.

        # all_result 안에 결과를 저장하는 부분
        # with open(r"C:\malware\all_result\test_pelist.txt", 'w') as pelist:
        #     json.dump(self.pe_hash_dict, pelist, ensure_ascii=False, indent='\t')

        return self.pe_hash_dict

    def unpack_pe(self):
        Packer_Detect2.sample_packer_type_detect(self.pe_dir_path)

        sample_folder_path = self.pe_dir_path
        save_folder_path = r"C:\malware\packing_info"
        pack_path = os.path.join(save_folder_path, 'packed')
        unpack_path = os.path.join(save_folder_path, 'unpacked')
        if not (os.path.isdir(save_folder_path)): os.makedirs(save_folder_path)
        if not (os.path.isdir(pack_path)): os.makedirs(pack_path)
        if not (os.path.isdir(unpack_path)): os.makedirs(unpack_path)

        queue = unpack_module.mains(sample_folder_path)

        proc_list = []
        for _ in range(0, 5):
            proc = Process(target=unpack_module.packer_check, args=(queue, pack_path, unpack_path,))
            proc_list.append(proc)
        for proc in proc_list:
            proc.start()
        for proc in proc_list:
            proc.join()

def convert_idb(PATH,IDB_PATH):
    # idb 변환
    return pe2idb.create_idb(PATH, IDB_PATH)

def multiprocess_file(q, return_dict, flag):
    while q.empty() != True:
        f_path = q.get()

        if flag == 'idb':
            # 여기에 조건문 하나 더 추가해서 바로 idb 추출하는게 아니라 db에서 이미 뽑힌 정보 있는지 확인하고
            # 저장된게 있으면 해당 파일 정보 dict의 경로를 db에서 가져와서
            # json.load로 읽어서 dict를 받음

            # if db 미 존재
            file_filter = f_path[f_path.rfind('\\') + 1:-4]

            try:
                file = Filter.objects.get(filehash=file_filter)
            except Filter.DoesNotExist:
                file = None

            if file is not None:
                fd1 = open(file.idb_filepath + ".txt", "rb")
                info = json.loads(fd1.read(), encoding='utf-8')
                fd1.close()
                #print('idb존재함')
            elif file is None:
                info = extract_asm_and_const.basicblock_info_extraction(f_path)  # 함수대표값 및 상수값 출력
                with open(r"C:\malware\all_result\idb" + "\\" + file_filter + ".txt", 'w') as makefile:
                    json.dump(info, makefile, ensure_ascii=False, indent='\t')
                Filter.objects.create(filehash=info['file_name'], idb_filepath=idb_file_path + file_filter)
                #print('idb없음')

        elif flag == 'pe':

            file_filter2 = f_path[f_path.rfind('\\') + 1:]
            #print()

            try:
                pe_file = Filter.objects.get(filehash=file_filter2)
                #print(pe_file)
            except Filter.DoesNotExist:
                print('pe no db')
                pe_file = None

            try:
                pe_f = pe_file.pe_filepath
            except:
                pe_f = None

            if pe_f is not None:
                fd1 = open(pe_file.pe_filepath + ".txt", "rb")
                info = json.loads(fd1.read(), encoding='utf-8')
                fd1.close()
                with open(r"C:\malware\all_result\pe_r" + "\\" + file_filter2 + ".txt",  'w', -1, "utf-8") as makefile:
                    json.dump(info, makefile, ensure_ascii=False, indent='\t')
                print('pe존재함')
            elif pe_f is None:
            #try:
                pe = pefile.PE(f_path)
                info, pe_info_DB = extract_pe.Pe_Feature(f_path, pe).all()  # pe 속성 출력
                with open(r"C:\malware\all_result\pe" + "\\" + file_filter2 + ".txt", 'w', -1, "utf-8") as makefile:
                    json.dump(info, makefile, ensure_ascii=False, indent='\t')

                with open(r"C:\malware\all_result\pe_r" + "\\" + file_filter2 + ".txt", 'w', -1, "utf-8") as makefile:
                    json.dump(info, makefile, ensure_ascii=False, indent='\t')

                pe_file.pe_filepath = pe_file_path + file_filter2
                pe_file.save()
                pe.close()
                print('pe없음')
            #except Exception as e:
                # print('pe error !')
                # print(e)
                # continue

        return_dict[f_path] = info


class Exract_Feature:
    def __init__(self, path, idb_path):
        self.path = path
        self.idb_path = idb_path

    def export_by_multi(self, flag):

        if flag == 'idb':
            path = self.idb_path
        elif flag == 'pe':
            path = self.path

        try:
            q = Queue()
            manager = Manager()
            pe2idb.exe_list_to_queue(path, q)
            return_dict = manager.dict()

            procs = list()
            for i in range(os.cpu_count() // 2 + 1):
                proc = Process(target=multiprocess_file, args=[q, return_dict, flag])
                procs.append(proc)
                proc.start()
            for p in procs:
                p.join()
            return return_dict
        except:
            return False

    def export_idb_info(self, flag):

        export_idb = self.export_by_multi(flag)

        if export_idb != False:
            return export_idb
        else:
            return False

    def export_pe_info(self, flag):

        export_pe = self.export_by_multi(flag)

        if export_pe != False:
            return export_pe
        else:
            return False

class Analyze_files:
    def __init__(self, all_idb_info, all_pe_info):
        self.all_pe_info = all_pe_info
        self.all_idb_info = all_idb_info

    def calculate_heuristic(self, idb_result, pe_result):
        '''
                가중치가 부여된 점수들을 더해서 반환해주는 함수
                *다 더했을 때 최대나 최소안에 있는지 확인하는 로직을 넣어주고 예외처리 해주면 될 듯
                :return: final score
                '''
        # 최종 휴리스틱 스코어

        real_final = dict()

        for key_i, key_pe in zip(idb_result.items(), pe_result.items()):
            idb_final_score = dict()
            pe_final_score = dict()
            for value_i, value_pe in zip(key_i[1].items(), key_pe[1].items()):

                semifinal = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                semifinal[0] = (value_pe[1]['file_hash'])
                semifinal[1] = (value_pe[1]['time_date_stamp'])
                semifinal[2] = (value_i[1]['bbh'])
                semifinal[3] = (value_i[1]['const_value'][1])
                semifinal[4] = (value_pe[1]['section_score'])
                semifinal[5] = (value_pe[1]['cert_score'])
                semifinal[6] = (value_pe[1]['pdb_score'])
                semifinal[7] = (value_pe[1]['imphash'])
                semifinal[8] = (value_pe[1]['rich'])
                semifinal[9] = (value_pe[1]['rsrc'])
                semifinal[10] = (value_pe[1]['pe_all_score'])
                semifinal[11] = (value_i[1]['bbh'] + value_i[1]['const_value'][1] + value_pe[1]['pe_all_score'])

                idb_final_score[value_i[0]] = semifinal
                pe_final_score[value_pe[0]] = semifinal

            sorted(idb_final_score.items(), key=(lambda i: i[1][11]), reverse=True)

            real_final[key_i[0]] = idb_final_score
            real_final[key_pe[0]] = pe_final_score

        return real_final

    def analyze_idb(self):
        idb = analyze_flowchart.AnalyzeFlowchart(self.all_idb_info)
        idb_result = idb.analyze_all()

        return idb_result

    def analyze_pe(self):
        pe = analyze_pe.AnalyzePE(self.all_pe_info)
        pe_split = pe.pe_parser()
        pe_result = pe.analyze_all(pe_split)

        return pe_result

def create_folder():
    # mal_exe는 drag&drop할 때 먼저 생성됨
    # mal_idb, all_result(idb, pe) 가 없으면 생성

    default_path = ["C:\\malware\\mal_idb\\","C:\\malware\\all_result\\", "C:\\malware\\all_result\\idb", "C:\\malware\\all_result\\pe\\", "C:\\malware\\all_result\\pe_r\\", "C:\\malware\\all_result\\cg\\", "C:\\malware\\all_result\\cfg\\","C:\\malware\\error\\"]
    for path in default_path:
        if os.path.exists(path):
            continue
        else:
            os.makedirs(path)

def delete_file():
    default_path = ["C:\\malware\\mal_idb\\", "C:\\malware\\mal_exe\\"]

    for path in default_path:
        if os.path.exists(path):
            for file in os.scandir(path):
                print(file.path)
                os.remove(file.path)
            print('Remove All File')
        else:
            print('Directory Not Found')


def start_engine():
    '''
    웹 서버에서 메인 엔진을 호출하면 엔진을 돌리기위한 함수
    '''
    PATH = r"C:\malware\mal_exe"
    IDB_PATH = r"C:\malware\mal_idb"

    # 0. 없는 폴더 먼저 생성
    #create_folder()

    # 1. pe 해시 체크 (동일한 파일 필터), 2.패킹 체크
    print("1) hash check")
    hash_check = "hash_check"
    pe_check = Pe_Files_Check(PATH)
    print("2) packing check")
    file_hash_dict = pe_check.get_unique_pe_list()

    # 3. pe파일(+패킹 체크) -> idb 변환
    print("3) idb converter")
    flag = convert_idb(PATH, IDB_PATH)
    Features = Exract_Feature(PATH, IDB_PATH)

    # 4. 정보 추출(idb,pe)
    if flag == True:
        print("4) extract IDB and PE")
        all_idb_info = Features.export_idb_info('idb')
        all_pe_info = Features.export_pe_info('pe')
        #print("5) Machine Learning")
        #ML_result_data=idb_pe_feature(all_idb_info, all_pe_info)
        #print(ML_result_data)
    else:
        print('convert_idb is error')

    # 5. 분석 하기
    print("5) Analyze file")
    analyze = Analyze_files(all_idb_info, all_pe_info)

    result_pe = analyze.analyze_pe()
    result_idb = analyze.analyze_idb()

    print("6) Result SAVE")
    # 6. 결과 저장
    all_result = analyze.calculate_heuristic(result_idb, result_pe)

    return all_result

# def idb_pe_feature(all_idb_info,all_pe_info):
#     #print("allPeinfo:{}".format(all_pe_info))
#     extract_pe_class = new_getinfo_pe.getinfo_pe()
#     model = joblib.load(os.getcwd()+"\\Main_engine\\ML\\"+'ML_model2.pkl')
#
#     ML_result_data = dict()
#     for pe_info in all_pe_info.keys():
#         file_full_path=all_pe_info[pe_info]['file_path']
#         file_base_name = all_pe_info[pe_info]['file_name']
#         # print(file_full_path)
#         # print(file_base_name)
#         for idb_info in all_idb_info.keys():
#
#             if all_idb_info[idb_info]['file_name']==file_base_name:
#             #if idb_info['file_name']==file_base_name:
#                 result_opcoded_count_dict = {'MOV': 0, 'LEA': 0, 'ANDL': 0, 'JE': 0, 'ADD': 0, 'SBB': 0, 'SUB': 0, 'INT3': 0,\
#                                              'SHR': 0, 'OR': 0, 'JB': 0, 'DEC': 0, 'DECL': 0, 'INCL': 0, 'FXCH': 0, 'JP': 0, \
#                                              'FSTP': 0, 'NOT': 0, 'PUSHF': 0, 'XCHG': 0, 'ADC': 0, 'CLC': 0, 'LCALL': 0, 'AAA': 0, \
#                                              'FIADDL': 0, 'OUTSL': 0, 'XLAT': 0, 'ROLL': 0, 'LES': 0, 'OUTSB': 0, 'AAM': 0, 'DAS': 0, \
#                                              'CLD': 0, 'NOTB': 0, 'IRET': 0, 'FSTPS': 0, 'SS': 0, 'CMC': 0, 'RORB': 0, 'FNSAVE': 0,\
#                                              'FLDS': 0, 'FIADD': 0, 'JNO': 0, 'INCB': 0, 'CMPW': 0, 'ABCL': 0, 'MOVSWL': 0, 'SHRL': 0, \
#                                              'CPUID': 0, 'FIMUL': 0, 'RORL': 0, 'SAL': 0, 'FNCLEX': 0, 'SETG': 0, 'FSUBL': 0, 'FCMOVU': 0,\
#                                              'PSUBB': 0, 'DIVB': 0, 'RCRL': 0, 'MOVQ': 0, 'RDTSC': 0, 'RDPMC': 0, 'PCMPEQB': 0, 'FBLD': 0, \
#                                              'FCMOVB': 0, 'FUCOMI': 0, 'FLDLG2': 0, 'FABS': 0, 'FCHS': 0, 'PREFETCHNTA': 0, 'XGETBV': 0, \
#                                              'PI2FW': 0, 'FSTSW': 0, 'ADDPD': 0, 'DIVSD': 0, 'PALIGNR': 0, 'GETSEC': 0}
#
#                 for fname, value_1 in all_idb_info[idb_info]['func_name'].items():
#                     if fname != "constant":
#                         for sAddr, value_2 in value_1.items():
#                             if sAddr != "flow_opString" and sAddr != "flow_constants" and sAddr != "flow_branches":
#                                 opcode_list=[opcode.upper() for opcode in all_idb_info[idb_info]['func_name'][fname][sAddr]['opcodes']]
#                                 for opcode in opcode_list:
#                                     try:
#                                         result_opcoded_count_dict[opcode]+=1
#                                     except KeyError:continue
#                 op_list_count = list(result_opcoded_count_dict.values())
#
#                 pe_result_data=extract_pe_class.predict_peature_get_info(file_full_path)
#                 size_label=pe_result_data[-1:]
#                 pe_result_data=pe_result_data[:-1]
#                 pe_result_data+=op_list_count
#                 pe_result_data +=size_label
#                 predict_labels = model.predict([pe_result_data])[0]
#                 #predict_labels 0 은 비악성 1은 악성
#                 ML_result_data[file_base_name]=predict_labels
#     return ML_result_data
