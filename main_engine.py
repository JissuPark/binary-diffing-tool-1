import json
import timeit
import os

from Analzer_Engine import Analyzer_main
from Extract_Engine import pe2idb
from Extract_Engine.Flowchart_feature import extract_asm_and_const
from Extract_Engine.PE_feature import Export_Pe_Main
import pefile
import idb

class Analye_Simularity:
    def __init__(self):
        print('hello')

class Exract_Feature:
    def __init__(self,PATH,IDB_PATH):
        self.PATH=PATH
        self.IDB_PATH=IDB_PATH

    def export_idb(self):
        flag = pe2idb.create_idb(PATH, IDB_PATH)  # idb 변환
        return flag

    def export_pe(self):
        print('hello')

if __name__ == "__main__":
    PATH = r"D:\JungJaeho\STUDY\self\BOB\BoB_Project\Team_Breakers\Training\Study\sample\mid_GandCrab_exe"
    IDB_PATH = r"D:\JungJaeho\STUDY\self\BOB\BoB_Project\Team_Breakers\Training\Study\sample\mid_idb"

    '''
        idb 변환 및 pe 추출을 멀티 프로세싱을 돌리는 로직 추가
    '''

    Features = Exract_Feature(PATH,IDB_PATH)
    flag = Features.export_idb()

    if flag == True:
        for idb in os.listdir(IDB_PATH):
            idb_sub_function_info = extract_asm_and_const.basicblock_idb_info_extraction(
                IDB_PATH + '\\' + idb)  # 함수대표값 및 상수값 출력

        with open(r"D:\JungJaeho\STUDY\self\BOB\BoB_Project\Team_Breakers\Training\Study\sample\result\test.txt",
                  'w') as makefile:
            json.dump(idb_sub_function_info, makefile, ensure_ascii=False, indent='\t')

    else:
        print('fuck')
        # git testing
        print('test ~ ,. ~')




