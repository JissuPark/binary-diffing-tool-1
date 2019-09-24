import os
from multiprocessing import Process, Queue
import pefile
import hashlib
import time
import timeit
import subprocess
import shutil

'''
    Developed by seonaelee
'''

# idat.exe / idat64.exe 구분하여 실행하기 위함.
IDAT   = 0
IDAT64 = 1

PE_CHECK_ERROR = -1

STR_SIG_MZ = '0x4550'
HEX_M_32 = 0x14c
HEX_M_64 = 0x200

# IDAT_PATH
# 나중에 자동으로 받아올지 생각해보기
IDAT_PATH=[
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
    try:
        pe=pefile.PE(PE_F_PATH,fast_load=True)
        m_bit=pe.FILE_HEADER.Machine
        signature_hex=hex(pe.NT_HEADERS.Signature)
        pe.close()
        if signature_hex== STR_SIG_MZ:
            if m_bit == HEX_M_32:
                return IDAT
            elif m_bit == HEX_M_64:
                return IDAT64
        else:
            return PE_CHECK_ERROR
    except:
        return PE_CHECK_ERROR



'''
 * file_to_hash                                                                        
                                                                                     
  -. 파일의 바이너리를 입력값으로 sha256한 값을 반환한다.
  -. Return the sha256 hash digest value of the PE_F_PATH

    (보통 악성코드 분석시 해당 파일의 해시값을 파일명으로 지정하는 경우가 많다고         
      현목이가 그래서 일단 시간도 별로 안걸리는 부분이라 넣었어요) 

'''
def file_to_hash(PE_F_PATH):
    return hashlib.sha256(open(PE_F_PATH,'rb').read()).hexdigest()



'''
 * exe_list_to_queue                                                                   
                                                                                     
  -. idb로 변환하려는 PE파일의 디렉토리의 모든 파일들의 이름을 hash로 변경하고 큐에 삽입.
  -. Change the names of files in the PE_D_PATH and insert the file paths into queue     

'''
def exe_list_to_queue(PE_D_PATH, q):
    # 인자로 받은 PE 파일이 위치한 디렉토리의 모든 파일의 리스트(exe_list)를 가져옴.
    exe_list = os.listdir(PE_D_PATH)
    for f in exe_list:
        f_path = os.path.join(PE_D_PATH, f)
        h = file_to_hash(f_path)
        h_path = os.path.join(PE_D_PATH, h)

        os.rename(f_path,os. path.join(f_path,os.path.join(PE_D_PATH, h)))        
        q.put(h_path)



'''
 *  exec_idat                                                                           
                                                                                     
 -. pe_flag에 따라 32bit CPU이면 idat.exe를, 64bit CPU이면 idat64.exe를 실행하고        
    해당 자식프로세스를 반환한다.                                                       
 -. Execute the idat.exe or idat64.exe and then return the child process                

'''
def exec_idat(EXE_F_PATH, pe_flag):
    if pe_flag==IDAT or pe_flag==IDAT64:
        # -A :
        # -B : batch mode. IDA는 .IDB와 .ASM 파일을 자동 생성한다.
        # -P : 압축된 idb를 생성한다.
        process=subprocess.Popen([IDAT_PATH[pe_flag],"-A","-B","-P+",EXE_F_PATH], shell=True)
        return process        
    else:
        # pe_flag가 IDAT(0) 혹은 IDAT(1)이 아닌 경우에는
        # 먼저 idat.exe을 실행한다.
        # idat.exe 실행에서 exception 발생 시, idat64.exe를 실행한다. 
        try:
            process=subprocess.Popen([IDAT_PATH[IDAT],"-A","-B","-P+",EXE_F_PATH], shell=True)
            return process
        except:
            process=subprocess.Popen([IDAT_PATH[IDAT64],"-A","-B","-P+",EXE_F_PATH], shell=True)
            return process



'''
 * exe_to_idb                                                                          
                                                                                     
 -. exe_q에 삽입해 둔 PE 파일의 경로를 큐에서 가져와서                                  
    머신비트에 따라 idat을 실행하도록 한다.                                             
 -. Call exec_idat with argument PE file path and pe machine bit value                  
    And then wait the termination of the child process for cleaning the folder.          

'''
def exe_to_idb(exe_q): ### Multiprocessing할 때, target의 인자로 넘길 함수
    while exe_q.empty() != True:
        # exe_q에 삽입된 PE 파일 디렉토리 경로를 가져와서
        # pe 포맷인지 확인(pe_check 호출)
        f_path = exe_q.get()
        pe_flag = pe_check(f_path)

        # 만약 PE 포맷이라면
        # exec_idat을 호출해서 diat을 실행하고 
        if pe_flag != PE_CHECK_ERROR:
            # exec_idat을 실행하고 해당 자식프로세스가 끝날 때까지 기다린다.
            # 기다렸다가 idat 실행 후, 생성되는 파일을 정리해야하기 때문에
            # idat 실행이 종료될 때까지 기다린다.
            p = exec_idat(f_path, pe_flag)
            p.wait()



'''
 * clear_folder                                                                        
                                                                                     
 -. .idb, .i64를 IDB_PATH 폴더로 복사하고 PATH 경로에서 PE파일를 제외한 파일을 삭제한다.          
 -. Copy .idb and .i64 files to IDB_PATH directory
    And then delete all files except for PE files in the PATH directory
 
'''
def clear_folder(EXE_F_PATH, IDA_F_PATH):
    exe_list = os.listdir(EXE_F_PATH)
    try:
        for f in exe_list:
            if os.path.splitext(f)[-1] == ".idb" or os.path.splitext(f)[-1] == ".i64":
                shutil.copy(os.path.join(EXE_F_PATH,f), os.path.join(IDA_F_PATH,f))
                os.remove(EXE_F_PATH+"\\"+f)
            elif '.' in f:
                os.remove(EXE_F_PATH+"\\"+f)
        return True
    except:
        return False



'''
 * convert_pe_to_idb

 -. 예시
    convert_pe_to_idb(r"D:\Breakers\idb_sample",r"D:\Breakers\test_exe_sample")
                                                                                     
 -. PE_PATH의 PE파일들을 IDB 파일로 변환하여 IDB_PATH디렉토리에 저장한다.         
 -. Convert PE files to IDB files and then store the IDB files in the IDB_PATH directory. 

'''
def convert_pe_to_idb(IDB_PATH, PE_PATH):
    
    ### time idb로 파일을 변환하는 시간 측정을 위한 코드
    s = timeit.default_timer()
    
    # exe_q에 idb로 변환할 exe파일을 쌓는다
    exe_q=Queue()
    
    # exe_q에 변환할 파일들을 삽입해둠.
    exe_list_to_queue(PE_PATH, exe_q)
    
    ##################### START - Multiprocessing ######################
    procs = list()
    for i in range(os.cpu_count()//2+1):
        proc=Process(target=exe_to_idb, args=[exe_q, ])
        procs.append(proc)
        proc.start()
    # join() : multiprocessing하는 프로세스 종료까지 기다린다.
    for p in procs:
        p.join()
    ###################### END - Multiprocessing #######################

    clear_folder(PE_PATH,IDB_PATH)    
    print(f"[=]TERMINATE")
    ### time
    print(f"[+]time : {timeit.default_timer() - s}")

    return True


'''
 test를 위한 main 함수

'''
def create_idb(PATH,IDB_PATH):
    
    ### time idb로 파일을 변환하는 시간 측정을 위한 코드
    s = timeit.default_timer()
    
    # exe_q에 idb로 변환할 exe파일을 쌓는다
    exe_q=Queue()

    # exe_q에 변환할 파일들을 삽입해둠.
    exe_list_to_queue(PATH, exe_q)
    
    ##################### START - Multiprocessing ######################
    procs = list()
    for i in range(os.cpu_count()//2+1):
        proc=Process(target=exe_to_idb, args=[exe_q, ])
        procs.append(proc)
        proc.start()
    # join() : multiprocessing하는 프로세스 종료까지 기다린다.
    for p in procs:
        p.join()
    ###################### END - Multiprocessing #######################

    ### time
    print(f"[+]time : {timeit.default_timer() - s}")

    return clear_folder(PATH,IDB_PATH)

# if __name__=="__main__":
#
#     # PATH : idb로 변환할 pe 파일이 위치한 디렉토리 경로
#     # IDB_PATH : 변환된 idb파일을 저장할 디렉토리 경로
#
#     PATH = r"D:\Breakers\test_exe_sample"
#     IDB_PATH = r"D:\Breakers\idb_sample"
#
#     create_idb(PATH,IDB_PATH)


