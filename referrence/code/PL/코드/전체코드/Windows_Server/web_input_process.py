
import M2push
import requests
import subprocess 
import sys
from distorm3 import DecomposeGenerator, Decode32Bits, Decode64Bits, Decode16Bits
import os
import shutil
import time
import psutil
import hashlib
import paramiko
import glob
import pefile
import pe_analyzer
import signal
import json
import math
from collections import OrderedDict
from datetime import datetime
from multiprocessing import Process, current_process,Queue, Pool, JoinableQueue
import threading

mutex_lists=[]
mutex_file=open('White_list.txt','r')
while True:
    line_data=mutex_file.readline()
    if not line_data:break
    mutex_lists.append(line_data)
mutex_file.close()


#########################################################################################################
def sha256_data(filename):
    file_object=open(filename,"rb")
    data=file_object.read()
    hash_sha256=hashlib.sha256(data).hexdigest().upper()
    file_object.close()
    return hash_sha256



##########################################################################################################
def pe_check(file_path):
    try:
        pe = pefile.PE(file_path, fast_load=True)
        # AddressOfEntryPoint if guaranteed to be the first byte executed.
        machine_bit = pe.FILE_HEADER.Machine
        signature_hex= hex(pe.NT_HEADERS.Signature)
        pe.close()
        if signature_hex=='0x4550':
            if machine_bit == 0x14c :

                return 'idat'

            elif machine_bit == 0x200 : 

                return 'idat64'

        else:
            return False
    except:
        return False
##########################################################################################################



####################################################################################################  
def convert_idb(sample_file_path,machine_bit):
    dt = Decode32Bits
    if machine_bit=='idat':
        ida_path = "C:\\Program Files\\IDA 7.0\\idat.exe"
    elif machine_bit=='idat64':
        ida_path = "C:\\Program Files\\IDA 7.0\\idat64.exe"
    else:
        try:
            ida_path = "C:\\Program Files\\IDA 7.0\\idat64.exe"
            process=subprocess.Popen([ida_path,"-A","-B","-P+",sample_file_path],shell=True)
            time.sleep(2)
            return process
        except:
            ida_path = "C:\\Program Files\\IDA 7.0\\idat.exe"
            process=subprocess.Popen([ida_path,"-A","-B","-P+",sample_file_path],shell=True)
            time.sleep(2)
            return process
    process=subprocess.Popen([ida_path,"-A","-B","-P+",sample_file_path],shell=True)
    time.sleep(2)
    return process
####################################################################################################


####################################################################################################
def getEntropy(FILENAME):
    ENTROPY_LIST={}
    PF=pefile.PE(FILENAME)
    for PE_SECTION in PF.sections:
        data = PE_SECTION.get_data()
        occurences = pefile.Counter(bytearray(data))
        entropy = 0
        for x in occurences.values():
            p_x = float(x) / len(data)
            entropy -= p_x*math.log(p_x, 2)
            

        try:
            
            ENTROPY_LIST[PE_SECTION.Name.decode().replace('\x00','').replace(".","dot")]=entropy
        except:
            
            ENTROPY_LIST

    PF.close()
    return ENTROPY_LIST
####################################################################################################



######################################
queue=JoinableQueue()
def Create_Process_Queue():
    while True:
        sample_default_path = "C:\\temp\\web_input\\pe_samples"

        sample_list=os.listdir(sample_default_path)
        for sample in sample_list:
            if '.' in sample:
                continue
            if '[' in sample:
                continue
            if '_' in sample:
                continue
            
            sample_full_path=os.path.join(sample_default_path,sample)
            
            #print(sample_full_path)
            if sample_full_path in queue_list:
                continue

            queue.put(sample_full_path)
            queue_list.append(sample_full_path)

#######################################

host = "118.219.252.231"
port = 22
transport = paramiko.Transport((host, port))
user = "bob"
passwd = "roqkfxmfor#123"
transport.connect(username=user, password=passwd)
sftp = paramiko.SFTPClient.from_transport(transport)
            

def create_json_idb():
    json_file_path =  "C:\\temp\\web_input\\json_samples"
    sample_default_path = "C:\\temp\\web_input\\pe_samples"
    idb_samples_path="C:\\temp\\web_input\\idb_samples"

    ubuntu_idb_sample_path_web_input="/home/bob/IDB_TMP/User_Sample/idb_samples"
    ubuntu_json_file_path_web_input="/home/bob/IDB_TMP/User_Sample/json_samples"

    
    group_sample_full_path=queue.get()
    
    
    queue_list.remove(group_sample_full_path)
    #Step 1 pe check
    #########################################################################################

    #step1-1
    group_sample_pe_check_result=pe_check(group_sample_full_path)
    sha256=sha256_data(group_sample_full_path)
    if group_sample_pe_check_result==False:
        try:
            os.remove(group_sample_full_path)
            m2push = M2push.M2push(url="https://m2lab.io", username="MASTER_ADMIN",
                api_key="900BB2D2300A947B90AB55B80D74A05376828EEEC816510CF2F1526AEEACCD6A")

            data = {
                "pe_success" : 0,
                "pe_random": os.path.basename(group_sample_full_path),
                "pe_sha256":sha256
            }

            print("Non Pe Send to web...")
            if m2push.send(data, type='win') is True:
                print("OK, success.")
            return
        except:
            return
    
    #step1-2
    if sha256 in mutex_lists:
        os.remove(group_sample_full_path)
        try:
            os.remove(group_sample_full_path)
            m2push = M2push.M2push(url="https://m2lab.io", username="MASTER_ADMIN",
                api_key="900BB2D2300A947B90AB55B80D74A05376828EEEC816510CF2F1526AEEACCD6A")

            data = {
                "pe_success" : 0,
                "pe_random": os.path.basename(group_sample_full_path),
                "pe_sha256":sha256
                }
            print("Non Pe Send to web...")
            if m2push.send(data, type='win') is True:
                print("OK, success.")
            return
        except:
            return

    #step1-3 upx unpack
    upx_pe=pefile.PE(group_sample_full_path)
    upx_flag=0
    for sections in upx_pe.sections:
        try:
            sname=sections.Name.decode().replace("\x00","").replace('.','dot')
        except:
            sname=sections.Name.decode('latin-1').encode('utf-8').decode('utf-8').replace('\x00','')
        
        if 'UPX' in sname:
            upx_pe.close()
            upx_flag=1
            subprocess.Popen(["upx.exe","-d",group_sample_full_path],shell=True)
            time.sleep(4)

    try:
        upx_pe.close()
        
    except:
        pass
    '''
    #step3
    if upx_flag==0:
        try:
            sample_basename=os.path.basename(group_sample_full_path)
            Entropy_dict=getEntropy(group_sample_full_path)
            if Entropy_dict['dottext'] > 6.85:
                subprocess.Popen(["MNM_Unpacker.exe","a",group_sample_full_path],shell=True)
                subprocess.Popen(["MNM_Unpacker.exe","f",group_sample_full_path],shell=True)
                time.sleep(4)
                Packed_list=glob.glob(sample_default_path+'\\*_')
                print(Packed_list)
                for Packed_Samples in Packed_list:
                    print(Packed_Samples)
                    if sample_basename in Packed_Samples:
                        os.remove(group_sample_full_path)
                        group_sample_full_path=os.path.join(sample_default_path,Packed_Samples)
                        break
        except:
            pass
    '''
    #Step 2 pe Information json file generation json file name should be Million Second
    #############################################################################

    pe_information=pe_analyzer.result_all(group_sample_full_path)
    
    pe_information['pe_groups']=None
    pe_information['pe_tags']=[None]
    pe_information=OrderedDict(pe_information)


    dt = datetime.now()
    json_file_name='{}{}{}{}{}{}'.format(dt.year,dt.month,dt.day,dt.hour,dt.minute,dt.microsecond)
    json_file_full_path=os.path.join(json_file_path,json_file_name)+'.json'
    with open(json_file_full_path, 'w', encoding="utf-8") as make_file:
        json.dump(pe_information, make_file, ensure_ascii=False, indent="\t")
    
    m2push = M2push.M2push(url="https://m2lab.io", username="MASTER_ADMIN",
                api_key="900BB2D2300A947B90AB55B80D74A05376828EEEC816510CF2F1526AEEACCD6A")

    print("Send to web...")
    if m2push.send(pe_information, type='win') is True:
        print("OK, success.")
        
    
    #Step 4 Create an idb file Enable the idat.exe process
    #############################################################################

    process=convert_idb(group_sample_full_path,group_sample_pe_check_result)

    max_time_end = time.time() + (60 * 2)
    flag=0

    while True:
        if time.time() > max_time_end:
            try:
                os.remove(group_sample_full_path)
                m2push = M2push.M2push(url="https://m2lab.io", username="MASTER_ADMIN",
                    api_key="900BB2D2300A947B90AB55B80D74A05376828EEEC816510CF2F1526AEEACCD6A")

                data = {
                        "pe_success" : 0,
                        "pe_random": os.path.basename(group_sample_full_path),
                        "pe_sha256":sha256
                    }
                print("Non Pe Send to web...")
                if m2push.send(data, type='win') is True:
                    print("OK, success.")
                return
            except:
                return            
            process.kill()
            return
        time.sleep(2)
        read_path_file_list=os.listdir(sample_default_path)
        for file_object in read_path_file_list:

            if '.idb' in file_object or '.i64' in file_object :
                idb_sample_full_path = os.path.join(sample_default_path,file_object)
                shutil.copy(idb_sample_full_path,os.path.join(idb_samples_path,file_object))

                ubuntu_group_path = ubuntu_idb_sample_path_web_input + '/' + file_object
                sftp.put(os.path.join(idb_samples_path,file_object), ubuntu_group_path)
                ubuntu_json_full_path=ubuntu_json_file_path_web_input+'/'+json_file_name+'.json'
                sftp.put(json_file_full_path,ubuntu_json_full_path)
                
                flag=1
                break
        if flag==1:
            break
    process.kill()

    remove_json_pefile(json_file_full_path,group_sample_full_path)
    #queue_list.remove(file_object.replace(".idb",""))
    #queue.task_done()

def remove_json_pefile(json_file_full_path,sample_full_path):
    try:
        sample_default_path = "C:\\temp\\web_input\\pe_samples"
        idb_samples_path="C:\\temp\\web_input\\idb_samples"
        json_file_path =  "C:\\temp\\web_input\\json_samples"

        
        os.remove(json_file_full_path)
        os.remove(sample_full_path)
        sample_base_name=os.path.splitext(os.path.basename(sample_full_path))[0]

        for sample_files in os.listdir(sample_default_path):
            if '.' in sample_files:
                if sample_base_name in sample_files:
                    os.remove(os.path.join(sample_default_path,sample_files))
    except:
        return




##########################################################################################################

queue_list=[]
if __name__=="__main__":
    
    threads_queue = threading.Thread(target=Create_Process_Queue, args=())
    threads_queue.daemon = True 
    threads_queue.start()
    create_json_idb()
    
    num_process=5

    while True:
        try:
            create_json_idb()
            time.sleep(5)
        except:
            sftp.close()
            host = "118.219.252.231"
            port = 22
            transport = paramiko.Transport((host, port))
            user = "bob"
            passwd = "roqkfxmfor#123"
            transport.connect(username=user, password=passwd)
            sftp = paramiko.SFTPClient.from_transport(transport)            
            time.sleep(5)
            continue
        
    
    '''
    while True:
        #create_json_idb()
        proc_list=[]
        for _ in range(num_process):
            proc=threading.Thread(target=create_json_idb,args=())
            proc_list.append(proc)
        for proc in proc_list:
            proc.daemon = True
            proc.start()
        for proc in proc_list:
            proc.join()
    
    proc_list=[]
    for _ in range(num_process):
        proc=Process(target=create_json_idb,args=())
        proc_list.append(proc)
    for proc in proc_list:
        proc.daemon = True
        proc.start()
    '''



    









