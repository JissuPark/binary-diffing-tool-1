import hashlib
from multiprocessing import Process, Queue, Manager
import subprocess
import shutil
import json
from Extract_Engine import pe2idb
import timeit
import os

from Analzer_Engine import Analyzer_main
from Extract_Engine import pe2idb
from Extract_Engine.Flowchart_feature import extract_asm_and_const
from Extract_Engine.PE_feature import Export_Pe_Main
from Analzer_Engine import Analyzer_main
import pefile
import idb
import csv

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
        # STR_SIG_MZ = '0x4550'
        # HEX_M_32 = 0x14c
        # HEX_M_64 = 0x200

    def get_unique_pe_list(self):
        exe_list = os.listdir(self.pe_dir_path)
        for f in exe_list:
            f_path = os.path.join(self.pe_dir_path, f)
            #f_hash = pe2idb.file_to_hash(f_path)
            f_hash = hashlib.sha256(open(f_path, 'rb').read()).hexdigest()

            # file hash 중복 = 완전히 같은 파일
            # 해당 파일은 삭제(이미 diffing할 동일 파일이 존재하므로)
            if f_hash in self.pe_hash_dict.values():
                os.remove(f_path)
            else:
                os.rename(f_path, os.path.join(self.pe_dir_path, f_hash))

                # 파일은 삭제하지만 해당 파일명(절대경로)와 해시정보는 DB에 있어야함.
            # 추후 시각화할 때 정보 필요
            self.pe_hash_dict[f_path] = f_hash

        # 이후에는 DB에 저장.
        # dictionary로 넘겨서 self.pe_hash_dict.value()의 유니크한 값들만 idb로 변환.
        # 나중에 서버에 올린 후에는 받은 파일 중 완전히 같은 파일은 서버 파일시스템에 저장하지 않는게 좋을 것 같다.
        # 예를 들어, file1, file2의 해시값이 동일한 경우
        # DB에는 file1과 file2의 파일명 그리고 해시값을 저장한다.
        # 그리고 서버 파일시스템 내에서 둘 중 하나의 파일은 지운다.
        # 일단 더 먼저 나오는 파일을 살리고 아닌 파일은 삭제하도록 하였다. 어차피 동일 파일이니깐.
        with open(r"C:\malware\result\test_pelist.txt", 'w') as pelist:
            json.dump(self.pe_hash_dict, pelist, ensure_ascii=False, indent='\t')

        return self.pe_hash_dict

def Convert_idb(PATH,IDB_PATH):
    # idb 변환
    return pe2idb.create_idb(PATH, IDB_PATH)

def multiprocess_file(q, return_dict, flag):

    while q.empty() != True:
        f_path = q.get()
        if flag == 'idb':
            info = extract_asm_and_const.basicblock_idb_info_extraction(f_path)  # 함수대표값 및 상수값 출력
        elif flag == 'pe':
            info = Export_Pe_Main.Pe_Feature(f_path).all()  # pe 속성 출력

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

        tmp = self.export_by_multi(flag)

        if tmp != False:
            count = 1
            #print(return_dict)
            for dict_list in tmp.values():
                with open(r"C:\malware\result\idbfile_"+str(count)+".txt", 'w') as makefile:
                    json.dump(dict_list, makefile, ensure_ascii=False, indent='\t')
                count = count + 1
            return tmp
        else:
            return False

    def export_pe(self, flag):

        tmp = self.export_by_multi(flag)

        if tmp != False:
            count = 1
            # print(return_dict)
            for dict_list in tmp.values():
                with open(r"C:\malware\result\pefile_" + str(count) + ".txt", 'w') as makefile:
                    json.dump(dict_list, makefile, ensure_ascii=False, indent='\t')
                count = count + 1
            return tmp
        else:
            return False

'''
    total score to the csv file
'''
def out_csv(csv_path, score_dict):
    with open(csv_path, 'w',  newline="") as csv_f:
        csv_w=csv.writer(csv_f)
        title = ['FILE NAME', 'FILE HASH', 'BB HASH', 'CONSTANT', 'IMPORT HASH','RICH', 'TOTAL SCORE']
        i=1
        csv_w.writerow(title)
        for key, score_row in score_dict.items():
            score_row.append(f"=sum(C{i}, D{i}, E{i}, F{i})")
            i+=1
            result_row = [key]
            for v in score_row:
                result_row.append(v)
            csv_w.writerow(result_row)

if __name__ == "__main__":

    s = timeit.default_timer()

    PATH = r"C:\malware\mid_GandCrab_exe"
    IDB_PATH = r"C:\malware\mid_idb"


    ########################### pe 체크 ######################################
    test = Pe_Files_Check(PATH)
    test.get_unique_pe_list()
    print("for slack/git test")

    # 해당 로직의 최종 결과물로 필터링된 pe 파일들이 담긴 경로가 저장됨
    ##########################################################################

    ########################### idb의 정보 추출 로직################################

    flag = Convert_idb(PATH, IDB_PATH)

    Features = Exract_Feature(PATH, IDB_PATH)

    if flag == True:
        all_idb_info = Features.export_idb_info('idb')
        all_pe_info = Features.export_pe('pe')
    else:
        print('dd')


    if all_idb_info == False:
        print('예외처리 로직')
    else:
        print('정상')
    ##############################################################################


    ########################### 모든 특징 분석 로직 #####################################
    # Analyzer = Analyzer_main.AnalyzeSimilarity(all_idb_info, all_pe_info)
    # Analyzer.analyze_parser()
    # result = Analyzer.calculate_heuristic()
    ##################################################################################


    ########################### 최종 결과물 csv 추출 ###################################

#     dict ={"file1":["0x123",1, 2, 3, 4, 5, 6],
#            "file2":["0x456",1, 2, 3, 4, 5, 6],
#            "file3":["0x789",1, 2, 3, 4, 5, 6],
#            "file4":["0x012",1, 2, 3, 4, 5, 6],
#            "file5":["0x345",1, 2, 3, 4, 5, 6],
#         }
    #out_csv(r"D:\JungJaeho\STUDY\self\BOB\BoB_Project\Team_Breakers\Training\Study\sample\result\test.csv", result)
    ##################################################################################

    print(f"[+]time : {timeit.default_timer() - s}")