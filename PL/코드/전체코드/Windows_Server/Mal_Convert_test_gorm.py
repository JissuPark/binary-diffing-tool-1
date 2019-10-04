

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
import pefile
import pe_analyzer
import json
import glob
import signal
from collections import OrderedDict
from datetime import datetime
from multiprocessing import Process, current_process,Queue, Pool



#######################################################################################################
mutex_lists=[]
mutex_file=open('White_list.txt','r')
while True:
    line_data=mutex_file.readline()
    if not line_data:break
    mutex_lists.append(line_data)
mutex_file.close()



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
            print("Fails")
            return False
    except:
            print("Removes : {}".format(file_path))
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
            ida_path = "C:\\Program Files\\IDA 7.0\\idat.exe"
            process=subprocess.Popen([ida_path,"-A","-B","-P+",sample_file_path],shell=True)
            time.sleep(2)
            return process
        except:
            ida_path = "C:\\Program Files\\IDA 7.0\\idat64.exe"
            process=subprocess.Popen([ida_path,"-A","-B","-P+",sample_file_path],shell=True)
            time.sleep(2)
            return process
    process=subprocess.Popen([ida_path,"-A","-B","-P+",sample_file_path],shell=True)
    time.sleep(2)
    return process
####################################################################################################
json_file_path = "C:\\temp\\json"
idb_sample_default_path = "C:\\temp\\idb_sample"
sample_default_path = "C:\\temp\\pe_sample"



group_None_list=['kimsuky','DarkHotel']
def Create_Process_Queue(queue):
    json_file_path = "C:\\temp\\json"
    idb_sample_default_path = "C:\\temp\\idb_sample"
    sample_default_path = "C:\\temp\\pe_sample"


    ubuntu_idb_sample_path_web_input="/workspace/MandM_DB_INSERT3/IDB_TMP/Idb_Sample"
    ubuntu_json_file_path_web_input="/workspace/MandM_DB_INSERT3/IDB_TMP/json"
    
    for json_sample in os.listdir(json_file_path):
        json_sample_full_path=os.path.join(json_file_path,json_sample)
        sftp.put(json_sample_full_path, ubuntu_json_file_path_web_input+'/'+json_sample)
        os.remove(json_sample_full_path)
    
    sample_group_list=os.listdir(sample_default_path)
    for groups in sample_group_list:
        if groups not in group_None_list:
            continue
        if '.py' in groups:
            continue
        group_file_lists=os.listdir(os.path.join(sample_default_path,groups))
        for group_sample in group_file_lists:
            group_sample_full_path=os.path.join(sample_default_path,groups,group_sample)
            try:
                if '.' in group_sample:
                    if '.idb' in group_sample or '.i64' in group_sample:
                        sftp.put(group_sample_full_path, ubuntu_idb_sample_path_web_input+'/'+group_sample)
                        os.remove(group_sample_full_path)
                        
                    os.remove(group_sample_full_path)
                
                
            except:
                continue

            queue.put([group_sample_full_path,groups])


####################################################################################################

host = "13.125.159.173"
port = 58037
transport = paramiko.Transport((host, port))
user = "bob7"
passwd = "qldhql1234"
transport.connect(username=user, password=passwd)
sftp = paramiko.SFTPClient.from_transport(transport)
            

def create_json_idb(queue):
    while True:
        json_file_path = "C:\\temp\\json"
        #idb_sample_default_path = "C:\\temp\\idb_sample"
        sample_default_path = "C:\\temp\\pe_sample"
        ubuntu_idb_sample_path_web_input="/workspace/MandM_DB_INSERT3/IDB_TMP/Idb_Sample"
        ubuntu_json_file_path_web_input="/workspace/MandM_DB_INSERT3/IDB_TMP/json"
        
        #print("\t pid : {}".format(os.getpid()))
        group_sample_full_path,groups=queue.get()
        print("{}".format(group_sample_full_path))
    
        #Step 1 pe check
        #########################################################################################
        group_sample_pe_check_result=pe_check(group_sample_full_path)
        if group_sample_pe_check_result==False:
            try:
                print("Removes : {}".format(group_sample_full_path))
                os.remove(group_sample_full_path)
                continue
            except:
                print("Error : {}".format(group_sample_full_path))
                continue



        #step1-2 upx unpack
        upx_pe=pefile.PE(group_sample_full_path)
        for sections in upx_pe.sections:
            try:
                sname=sections.Name.decode().replace("\x00","").replace('.','dot')
            except:
                sname=sections.Name.decode('latin-1').encode('utf-8').decode('utf-8').replace('\x00','')
            
            if 'UPX' in sname:
                try:
                    upx_pe.close()
                    process=subprocess.Popen(["upx.exe","-d",sample_path],shell=True)
                except:
                    continue
        try:
            upx_pe.close()
            process.kill()
        except:
            pass


        

        #Step 2 pe Information json file generation json file name should be Million Second
        #############################################################################
        pe_information=pe_analyzer.result_all(group_sample_full_path)
        pe_information['pe_groups']=groups
        pe_information['pe_tags']=["private",groups]
        pe_information=OrderedDict(pe_information)

        
        dt = datetime.now()
        json_file_name='{}{}{}{}{}{}'.format(dt.year,dt.month,dt.day,dt.hour,dt.minute,dt.microsecond)
        json_file_full_path=os.path.join(json_file_path,json_file_name)+'.json'
        with open(json_file_full_path, 'w', encoding="utf-8") as make_file:
            json.dump(pe_information, make_file, ensure_ascii=False, indent="\t")


        #Step 3 Create an idb file Enable the idat.exe process
        #############################################################################
        process=convert_idb(group_sample_full_path,group_sample_pe_check_result)

        max_time_end = time.time() + (60 * 2)
        flag=0
        while True:
            if time.time() > max_time_end:
                os.remove(group_sample_full_path)
                process.kill()
                break

            #read_path_file_list => full_sample_path!!        
            read_path_file_list=glob.glob(group_sample_full_path+'*')
            if read_path_file_list==[]:
                time.sleep(2)
                continue
            for file_object in read_path_file_list:
                file_object_basname=os.path.basename(file_object)

                if '.idb' in file_object_basname or '.i64' in file_object_basname:
                    group_idb_sample_full_path = os.path.join(sample_default_path, groups, file_object_basname)

                    ubuntu_group_path = ubuntu_idb_sample_path_web_input + '/' + file_object_basname
                    sftp.put(group_idb_sample_full_path, ubuntu_group_path)
                    
                    ubuntu_json_full_path=ubuntu_json_file_path_web_input+'/'+json_file_name+'.json'
                    sftp.put(json_file_full_path,ubuntu_json_full_path)
                    #print("Success : {} ".format(file_object))
                    flag=1
                    break

            if flag==1:
                break
        process.kill()
        remove_json_pefile(json_file_full_path,group_sample_full_path,groups)

#########################################################################################
def remove_json_pefile(json_file_full_path,sample_full_path,groups):
    try:
        json_file_path = "C:\\temp\\json"
        idb_sample_default_path = "C:\\temp\\idb_sample"
        sample_default_path = "C:\\temp\\pe_sample"

        
        os.remove(json_file_full_path)
        os.remove(sample_full_path)

        #sample basename        
        sample_base_name=os.path.splitext(os.path.basename(sample_full_path))[0]

        #group lists
        sample_group_list=os.listdir(sample_default_path)
        for groups in sample_group_list:
            if '.py' in groups:
                continue
            group_file_lists=os.listdir(os.path.join(sample_default_path,groups))
            
            for group_sample in group_file_lists: 
                if '.' in group_sample:
                    #.idb idc remove...
                    if sample_base_name in group_sample:
                        os.remove(os.path.join(sample_default_path,groups,group_sample))
            
    except:
        return
        
##########################################################################################################
def file_count():
    dirs='C:\\temp\\pe_sample'
    sample_group_list=os.listdir(dirs)
    count=0
    for groups in sample_group_list:
        if '.py' in groups:
            continue
        group_file_lists=os.listdir(os.path.join(dirs,groups))
        for _ in group_file_lists:
            count=count+1
    return count
##########################################################################################################
if __name__=="__main__":
    queue=Queue()
    Create_Process_Queue(queue)

    
    #create_json_idb(queue)
    

    while True:
        proc_list=[]
        for _ in range(0,5):
            proc=Process(target=create_json_idb,args=(queue,))
            proc_list.append(proc)
        for proc in proc_list:
            proc.start()
        for proc in proc_list:
            proc.join()
    
