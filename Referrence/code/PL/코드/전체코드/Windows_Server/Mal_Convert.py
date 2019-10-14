

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
from collections import OrderedDict
from datetime import datetime
from multiprocessing import Process, current_process,Queue, Pool

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
json_file_path = "C:\\temp\\json"
idb_sample_default_path = "C:\\temp\\idb_sample"
sample_default_path = "C:\\temp\\pe_sample"


def Create_Process_Queue():
    json_file_path = "C:\\temp\\json"
    idb_sample_default_path = "C:\\temp\\idb_sample"
    sample_default_path = "C:\\temp\\pe_sample"
    while True:
        sample_group_list=os.listdir(sample_default_path)
        for groups in sample_group_list:
            if '.py' in groups:
                continue
            group_file_lists=os.listdir(os.path.join(sample_default_path,groups))
            for group_sample in group_file_lists:
                group_sample_full_path=os.path.join(sample_default_path,groups,group_sample)
                try:
                    if '.' in group_sample:
                        os.remove(group_sample_full_path)
                    elif '[' in group_sample:
                        os.remove(group_sample_full_path)
                    elif '_' in group_sample:
                        os.remove(group_sample_full_path)
                except:
                    continue

        sample_group_list=os.listdir(sample_default_path)
        for groups in sample_group_list:
            if '.py' in groups:
                continue
            group_file_lists=os.listdir(os.path.join(sample_default_path,groups))
            for group_sample in group_file_lists:
                group_sample_full_path=os.path.join(sample_default_path,groups,group_sample)

                #Step 1 pe check
                #########################################################################################
                group_sample_pe_check_result=pe_check(group_sample_full_path)
                if group_sample_pe_check_result==True:
                    pass
                elif group_sample_pe_check_result==False:
                    os.remove(group_sample_full_path)
                    continue
                queue.put([group_sample_full_path,groups])




#######################################
def create_json_idb(queue):
    #json_file_path = "C:\\temp\\json"
    #idb_sample_default_path = "C:\\temp\\idb_sample"
    #sample_default_path = "C:\\temp\\pe_sample"

    while queue.empty()!=True:
        print("\t pid : {}".format(os.getpid()))
        group_sample_full_path,groups=queue.get()

        #Step 3 pe Information json file generation json file name should be Million Second
        #############################################################################
        pe_information=pe_analyzer.result_all(group_sample_full_path)
        pe_information['pe_groups']=groups
        pe_information['pe_tags']=["private",groups]
        pe_information=OrderedDict(pe_information)

        
        dt = datetime.now()
        json_file_name='{}{}{}{}{}{}'.format(dt.year,dt.month,dt.day,dt.hour,dt.minute,dt.microsecond)
        json_file_full_path=os.path.join(json_file_path,json_file_name)
        with open(json_file_full_path+'.json', 'w', encoding="utf-8") as make_file:
            json.dump(pe_information, make_file, ensure_ascii=False, indent="\t")
        

        #Step 4 Create an idb file Enable the idat.exe process
        #############################################################################
        convert_idb(group_sample_full_path)

        max_time_end = time.time() + (60 * 1)
        while True:
            if time.time() > max_time_end:
                break
            time.sleep(2)
            read_path_file_list=os.listdir(os.path.join(sample_default_path,groups))
            for file_object in read_path_file_list:
                if os.path.splitext(file_object)[0].lower()==os.path.basename(os.path.splitext(group_sample_full_path)[0]):
                    if '.idb' in file_object:
                        group_idb_sample_full_path = os.path.join(idb_sample_default_path, groups, file_object)
                        if groups not in os.listdir(idb_sample_default_path):
                            os.makedirs(os.path.join(idb_sample_default_path, groups))

                        # Move to the pe_sample->db_sample folder
                        #shutil.copy(group_sample_full_path, group_idb_sample_full_path)
                        break



#######################################
class file_move_remove:
    def __init__(self):
        self.json_file_path = "C:\\temp\\json"
        self.idb_sample_default_path = "C:\\temp\\idb_sample"
        self.sample_default_path = "C:\\temp\\pe_sample"
#Step 5 Move IDb file and delete other IDb impurities file
#########################################################################################
    def file_moves(self):
        sample_group_list=os.listdir(self.sample_default_path)
        for groups in sample_group_list:
            if '.py' in groups:
                continue
            group_file_lists=os.listdir(os.path.join(self.sample_default_path,groups))
            for group_sample in group_file_lists:
                group_sample_full_path=os.path.join(self.sample_default_path,groups,group_sample)

                if '.idb' in group_sample_full_path:
                    group_idb_sample_full_path=os.path.join(self.sample_default_path,groups,group_sample)
                    if groups not in os.listdir(self.idb_sample_default_path):
                        os.makedirs(os.path.join(self.idb_sample_default_path,groups))

                    #Move to the pe_sample->db_sample folder
                    #shutil.copy(group_sample_full_path,group_idb_sample_full_path)

    def file_remove(self):
        sample_group_list = os.listdir(self.sample_default_path)
        for groups in sample_group_list:
            if '.py' in groups:
                continue
            group_file_lists = os.listdir(os.path.join(self.sample_default_path, groups))

            for group_sample in group_file_lists:
                group_sample_full_path = os.path.join(self.sample_default_path, groups, group_sample)
                try:
                    if '.' in group_sample:
                        os.remove(group_sample_full_path)
                    if '[' in group_sample:
                        print(group_sample_full_path)
                        os.remove(group_sample_full_path)
                    if '_' in group_sample:
                        print(group_sample_full_path)
                        os.remove(group_sample_full_path)
                except:
                    continue
            
#Step 6 Send json and idb files uuntu
#########################################################################################
    def ubuntu_file_move(self):
        host="52.79.212.80"
        port=51278
        transport=paramiko.Transport((host,port))
        user="bob7"
        passwd="qldhql12#$"
        transport.connect(username = user, password = passwd)
        sftp = paramiko.SFTPClient.from_transport(transport)
        self.json_file_path="C:\\temp\\json"
        self.idb_sample_default_path="C:\\temp\\idb_sample"
        self.sample_default_path="C:\\temp\\pe_sample"

        self.ubuntu_idb_sample_path='/workspace/MandM_DB_INSERT3/IDB_TMP/Idb_Sample'
        self.ubuntu_json_file_path='/workspace/MandM_DB_INSERT3/IDB_TMP/json'

            #Send idb File Ubuntu
        idb_sample_group_list=os.listdir(self.sample_default_path)
        for groups in idb_sample_group_list:
            group_idb_file_lists=os.listdir(os.path.join(self.sample_default_path,groups))
            for group_idb_sample in group_idb_file_lists:
                if '.idb' in group_idb_sample:
                    group_idb_sample_full_path=os.path.join(self.sample_default_path,groups,group_idb_sample)
                    print(group_idb_sample_full_path)
                    ubuntu_group_path = self.ubuntu_idb_sample_path + '/' + group_idb_sample
                    sftp.put(group_idb_sample_full_path, ubuntu_group_path)
        
            #Json File Ubuntu Transfer
        json_file_list=os.listdir(self.json_file_path)
        for json_files in json_file_list:
            json_files_full_path=os.path.join(self.json_file_path,json_files)

            ubuntu_json_full_path=self.ubuntu_json_file_path+'/'+json_files
            sftp.put(json_files_full_path,ubuntu_json_full_path)
        
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

if __name__=="__main__":
    queue = Queue()

    Create_Process_Queue(queue)
    proc_list=[]
    for _ in range(0,28):
        proc=Process(target=create_json_idb,args=(queue,))
        proc_list.append(proc)
    for proc in proc_list:
        proc.start()
