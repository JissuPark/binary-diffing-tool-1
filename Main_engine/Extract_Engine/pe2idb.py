import os
from multiprocessing import Process, Queue
import pefile
import hashlib
import time
import timeit
import subprocess
import shutil

from Main_engine.Check_Packing.Packer_Detect2 import sample_packer_type_detect
from Main_engine.Unpacking import unpack_module
from Main_engine.Unpacking.unpack_module2 import packer_check

'''
    Developed by seonaelee
'''

# idat.exe / idat64.exe 구분하여 실행하기 위함.
IDAT = 0
IDAT64 = 1

PE_CHECK_ERROR = -2
PE_UNKNOWN = -1
BYTES_SIG_MZ = b'MZ'   #'0x5A4D'
BYTES_SIG_PE = b'PE'   #'0x4550'
BYTES_SIG_IDB = b'IDA1'  # '0x31414449'
BYTES_SIG_I64 = b'IDA2'  # '0x32414449'

HEX_M_32 = 0x14c
HEX_M_64_IA = 0x200
HEX_M_64_AMD = 0x8664

#IDB_FLAG = -1

# IDAT_PATH
# 나중에 자동으로 받아올지 생각해보기
IDAT_PATH = [
    r"C:\Program Files\IDA 7.2\idat.exe",
    r"C:\Program Files\IDA 7.2\idat64.exe"
]

'''
#
  * pe_check                                                                            
   -. idb로 변환할 PE 파일의 PE MZ signature 확인 및 idat실행을 위한 머신 비트 확인   
   -. Check PE MZ signature and Machine bit The PE file(you want to convert to IDB file)  
      for executing the idat.exe/idat64.exe                                                                                                                                    

  * Return value                                                                         
     32bit CPU     0                                                                     
     64bit CPU     1                                                                     
     Error         -1                                                                    

'''
def pe_check(PE_F_PATH):

    f = open(PE_F_PATH, 'rb')
    f_data = f.read()
    f.close()

    # MZ signature & PE signature 확인
    if f_data[0:2] == BYTES_SIG_MZ and f_data[2:512].find(BYTES_SIG_PE) != -1:
        try:
            # pe format인거 확인 후, pefile 열기
            pe = pefile.PE(PE_F_PATH, fast_load=True)
            print('bbbbbbbbbbbbbb')
            m_bit = pe.FILE_HEADER.Machine
            #print(m_bit)
            pe.close()
            if m_bit == HEX_M_32:
                print(f"[32bit]{PE_F_PATH}")
                return IDAT
            
            elif m_bit == HEX_M_64_IA or m_bit == HEX_M_64_AMD:
                print(f"[64bit]{PE_F_PATH}")
                return IDAT64
            else:
                print(f"[64bit]{PE_F_PATH}")
                return IDAT64

        except:
            # pe format인데, 패킹되어 있는 경우 except로 들어올 것임.
            # pefile 모듈을 사용할 수 없기 때문
            # 이 경우 일단 idat.exe 돌리고, exception나면 idat64.exe으로..!
            print("PE_UNKNOWN - PACKING")
            return PE_UNKNOWN
    else:
        print("PE_CHECK_ERROR")        
        return PE_CHECK_ERROR



'''
 * exe_list_to_queue                                                                   

  -. idb로 변환하려는 PE파일의 디렉토리의 모든 파일들의 이름을 hash로 변경하고 큐에 삽입.
  -. Change the names of files in the PE_D_PATH and insert the file paths into queue     
'''


def exe_list_to_queue(PE_D_PATH, q):
    # 인자로 받은 PE 파일이 위치한 디렉토리의 모든 파일의 리스트(exe_list)를 가져옴.

    for f in os.listdir(PE_D_PATH):
        f_path = os.path.join(PE_D_PATH, f)
        q.put(f_path)
    # for index in PE_D_PATH:
    #     f_path = index
    #     q.put(f_path)
    return q


'''
 *  exec_idat                                                                           

 -. pe_flag에 따라 32bit CPU이면 idat.exe를, 64bit CPU이면 idat64.exe를 실행하고        
    해당 자식프로세스를 반환한다.                                                       
 -. Execute the idat.exe or idat64.exe and then return the child process                
'''


def exec_idat(EXE_F_PATH, pe_flag):
    print(pe_flag)
    if pe_flag == IDAT or pe_flag == IDAT64:
        # -A :
        # -B : batch mode. IDA는 .IDB와 .ASM 파일을 자동 생성한다.
        # -P : 압축된 idb를 생성한다.
        try:
            process = subprocess.Popen([IDAT_PATH[pe_flag], "-A", "-B", "-P+", EXE_F_PATH], shell=True)
            process.wait()
        except:
            print('errorrrrrrrrrrrrrr')
        return pe_flag
    #        return process
    else:
        # pe_flag가 IDAT(0) 혹은 IDAT(1)이 아닌 경우에는
        # 먼저 idat.exe을 실행한다.
        # idat.exe 실행에서 exception 발생 시, idat64.exe를 실행한다.
        try:
            process = subprocess.Popen([IDAT_PATH[IDAT], "-A", "-B", "-P+", EXE_F_PATH], shell=True)
            process.wait()
            return IDAT
        #            return process
        except:
            process = subprocess.Popen([IDAT_PATH[IDAT64], "-A", "-B", "-P+", EXE_F_PATH], shell=True)
            process.wait()
            return IDAT64


#           return process


'''
 * exe_to_idb                                                                          

 -. exe_q에 삽입해 둔 PE 파일의 경로를 큐에서 가져와서                                  
    머신비트에 따라 idat을 실행하도록 한다.                                             
 -. Call exec_idat with argument PE file path and pe machine bit value                  
    And then wait the termination of the child process for cleaning the folder.          
'''


def exe_to_idb(exe_q, pack_path, unpack_path,):  ### Multiprocessing할 때, target의 인자로 넘길 함수
    while exe_q.empty() != True:
        # exe_q에 삽입된 PE 파일 디렉토리 경로를 가져와서
        # pe 포맷인지 확인(pe_check 호출)
        f_path = exe_q.get()
        pe_flag = pe_check(f_path)

        # 만약 PE 포맷이라면
        # exec_idat을 호출해서 diat을 실행하고
        #if pe_flag == IDB_FLAG:
        #    continue
        print(pe_flag)
        if pe_flag != PE_CHECK_ERROR:
            # exec_idat을 실행하고 해당 자식프로세스가 끝날 때까지 기다린다.
            # 기다렸다가 idat 실행 후, 생성되는 파일을 정리해야하기 때문에
            # idat 실행이 종료될 때까지 기다린다.

            # 1. 파일 패킹 정보 저장 로직
            tmp = sample_packer_type_detect(f_path)
            print(tmp)

            # 2. 파일 언팩 수행 로직
            print('unpacke!!!!!!!!!!!!!!')
            packer_check(f_path, pack_path, unpack_path)

            p = exec_idat(f_path, pe_flag)
        else:
            print(f_path+'  '+'pe error')


#            p.wait()


'''
 * clear_folder                                                                        

 -. .idb, .i64를 IDB_PATH 폴더로 복사하고 PATH 경로에서 .asm 파일을 삭제한다.          
 -. Copy .idb and .i64 files to IDB_PATH directory
    And then delete all files except for PE files in the PATH directory

'''


def clear_folder(EXE_F_PATH, IDA_F_PATH):
    exe_list = os.listdir(EXE_F_PATH)
    try:
        for f in exe_list:
            if os.path.splitext(f)[-1] == ".idb" or os.path.splitext(f)[-1] == ".i64":
                # f_path=os.path.join(EXE_F_PATH,f) 사용할까 아님 이대로 할까 고민중..
                shutil.copy(os.path.join(EXE_F_PATH, f), os.path.join(IDA_F_PATH, f))
                os.remove(os.path.join(EXE_F_PATH, f))
            elif '.asm' in f:
                os.remove(os.path.join(EXE_F_PATH, f))
        return True
    except:
        return False


'''
 * create_idb

 -. 최종적으로 PATH 디렉토리 경로의 PE 파일들을 IDB파일로 변환해 IDB_PATH경로에 저장하는 함수
 -. main_engine.py 에서 이 함수를 호출함.  

'''


def create_idb(PE_PATH, IDB_PATH):
    ### time idb로 파일을 변환하는 시간 측정을 위한 코드
    #s = timeit.default_timer()

    # packing 관련
    sample_folder_path = PE_PATH
    save_folder_path = r"C:\malware\packing_info"
    pack_path = os.path.join(save_folder_path, 'packed')
    unpack_path = os.path.join(save_folder_path, 'unpacked')
    if not (os.path.isdir(save_folder_path)): os.makedirs(save_folder_path)
    if not (os.path.isdir(pack_path)): os.makedirs(pack_path)
    if not (os.path.isdir(unpack_path)): os.makedirs(unpack_path)

    #packing ..
    pack_q = Queue()
    exe_list_to_queue(PE_PATH,pack_q)

    # exe_q에 idb로 변환할 exe파일을 쌓는다
    exe_q = Queue()

    # exe_q에 변환할 파일들을 삽입해둠.
    exe_list_to_queue(PE_PATH, exe_q)

    ##################### START - Multiprocessing ######################
    procs = list()
    for i in range(os.cpu_count() // 2 + 1):
        proc = Process(target=exe_to_idb, args=[exe_q, pack_path, unpack_path, ])
        procs.append(proc)
        proc.start()
    # join() : multiprocessing하는 프로세스 종료까지 기다린다.
    for p in procs:
        p.join()
    ###################### END - Multiprocessing #######################
    #
    # proc_list = []
    # for _ in range(0, 5):
    #     proc = Process(target=unpack_module.packer_check, args=(pack_q, pack_path, unpack_path,))
    #     proc_list.append(proc)
    # for proc in proc_list:
    #     proc.start()
    # for proc in proc_list:
    #     proc.join()

    return clear_folder(PE_PATH, IDB_PATH)

if __name__=="__main__":

    # PATH : idb로 변환할 pe 파일이 위치한 디렉토리 경로
    # IDB_PATH : 변환된 idb파일을 저장할 디렉토리 경로

    PATH = r"C:\malware\mid_GandCrab_exe"
    IDB_PATH = r"C:\malware\mid_idb"

    create_idb(PATH, IDB_PATH)



