import json
import timeit
import os

from Analzer_Engine import Analyzer_main
from Extract_Engine import pe2idb
from Extract_Engine.Flowchart_feature import extract_asm_and_const
from Extract_Engine.PE_feature import Export_Pe_Main
import pefile
import idb

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
            f_hash = pe2idb.file_to_hash(f_path)

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
        with open(r"D:\JungJaeho\STUDY\self\BOB\BoB_Project\Team_Breakers\Training\Study\sample\result\test_pelist.txt", 'w') as pelist:
            json.dump(self.pe_hash_dict, pelist, ensure_ascii=False, indent='\t')

        return self.pe_hash_dict

def Convert_idb(PATH,IDB_PATH):
    flag = pe2idb.create_idb(PATH, IDB_PATH)  # idb 변환

    return flag

class Exract_Feature:
    def __init__(self,PATH,IDB_PATH):
        self.PATH=PATH
        self.IDB_PATH=IDB_PATH

    def export_idb_info(self, flag):
        if flag == True:
            for idb in os.listdir(IDB_PATH):
                idb_sub_function_info = extract_asm_and_const.basicblock_idb_info_extraction(IDB_PATH + '\\' + idb)  # 함수대표값 및 상수값 출력
        else:
            print('fuck you')

        return idb_sub_function_info

    def export_pe(self):
        print('hello')


def Export_All_Pe_Feature(TMP_Filter_PE_PATH):
    ppe = Export_Pe_Main.Pe_Feature(TMP_Filter_PE_PATH)
    test = ppe.all()
    return test
    #print(json.dumps(ppe.all(),indent=4))



if __name__ == "__main__":

    PATH = r"D:\JungJaeho\STUDY\self\BOB\BoB_Project\Team_Breakers\Training\Study\sample\mid_GandCrab_exe"
    IDB_PATH = r"D:\JungJaeho\STUDY\self\BOB\BoB_Project\Team_Breakers\Training\Study\sample\mid_idb"


    ########################### pe 체크 ######################################
    test = Pe_Files_Check(PATH)
    test.get_unique_pe_list()


    # 해당 로직의 최종 결과물로 필터링된 pe 파일들이 담긴 경로가 저장됨
    ##########################################################################






    ########################### idb의 정보 추출 로직################################

    flag = Convert_idb(PATH, IDB_PATH)
    Features = Exract_Feature(PATH, IDB_PATH)
    idb_sub_function_info = Features.export_idb_info(flag)

    with open(r"D:\JungJaeho\STUDY\self\BOB\BoB_Project\Team_Breakers\Training\Study\sample\result\test.txt", 'w') as makefile:
        json.dump(idb_sub_function_info, makefile, ensure_ascii=False, indent='\t')

    ################################################################################



    ########################### pe 특징 추출 로직 #####################################
    kkk=dict()
    TMP_Filter_PE_PATH=r"D:\JungJaeho\STUDY\self\BOB\BoB_Project\Team_Breakers\Training\Study\sample\mid_GandCrab_exe"
    TMP_Filter_PE_PATH2=r"D:\JungJaeho\STUDY\self\BOB\BoB_Project\Team_Breakers\Training\Study\sample\mid_GandCrab_exe\2cb5cfdc436638575323eac73ed36acd84b4694c144a754772c67167b99d574c"
    count = 0
    for pe in os.listdir(TMP_Filter_PE_PATH):
        a = Export_All_Pe_Feature(TMP_Filter_PE_PATH+ '\\' + pe)
        kkk[count]=a
        count=count+1

    kkk['count'] = count

    print(json.dumps(kkk, indent=4))

    ##################################################################################



    ########################### 모든 특징 분석 로직 #####################################

    #1. idb


    ##################################################################################





    ########################### 최종 결과물 csv 추출 ###################################

    # 1. idb

    ##################################################################################