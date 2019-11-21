import hashlib
import os
import sys
import threading
import shutil
import time

import subprocess
import yara
import math, array
import pefile
from multiprocessing import Process, current_process ,Queue, Pool

def cal_byteFrequency(byteArr, fileSize):
    freqList = []
    for b in range(256):
        ctr = 0
        for byte in byteArr:
            if byte == b:
                ctr += 1
        freqList.append(float(ctr) / fileSize)
    return freqList


def get_entropy(data):
    if len(data) == 0:
        return 0.0

    occurences = array.array('L', [0] * 256)
    for x in data:
        occurences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in occurences:
        if x:
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)

    return entropy

def get_file_bytes_size(filepath):
    Bin_value = []
    if filepath != None:
        with open(filepath, 'rb') as file_object:
            data = file_object.read(1)
            while data != b"":
                try:
                    Bin_value.append(ord(data))
                except TypeError:
                    pass
                data = file_object.read(1)

            return Bin_value, len(Bin_value)


def get_file_entropy(filepath):
    byteArr, fileSize = get_file_bytes_size(filepath)
    freqList = cal_byteFrequency(byteArr, fileSize)
    # Shannon entropy
    ent = 0.0
    for freq in freqList:
        if freq > 0:
            ent += - freq * math.log(freq, 2)

        # ent = -ent
    return [fileSize, ent]


#########################################################

yara_path="./peid.yara"
rules = yara.compile(filepath=yara_path)
#########################################################



def packer_check(queue):
    while queue.empty() != True:
        get_tuple= queue.get()
        sample_path=get_tuple[0]
        flags = get_tuple[1]




        if  flags==1:
            print("FSG")
            Unpacks_sub_process(sample_path, 1)
            #os.remove(sample_path)
            continue

        elif flags==2:
            print("UPX")
            Unpacks_sub_process(sample_path, 2)
            #os.remove(sample_path)
            continue
        elif flags==3:
            print("ASPACK")
            Unpacks_sub_process(sample_path, 3)
            #os.remove(sample_path)
            continue

    return



def Unpacks_sub_process(sample_path,flags):

    if flags==1:
        process_flag = subprocess.Popen(["MNM_Unpacker.exe", "a", sample_path], shell=True).wait()
        time.sleep(2)
        if process_flag == 1:
            print("Process Not Run")


    elif flags==2:
        print(sample_path)
        process_flag = subprocess.Popen(["upx.exe", "-d", sample_path], shell=True).wait()
        time.sleep(2)
        if process_flag == 1:
            process_flag2=subprocess.Popen(["upx2.exe", "-d", sample_path], shell=True).wait()
            if process_flag2 == 1:
                subprocess.Popen(["upx3.exe", "-d", sample_path], shell=True).wait()


    elif flags==3:
        process_flag = subprocess.Popen(["MNM_Unpacker.exe", "f", sample_path], shell=True).wait()
        if process_flag == 1:
            print("Process Not Run")

        time.sleep(2)



def mains():
    queue1 = Queue()
    folder_path = "D:\\Allinone\\Programing\\Python\\악성코드통합\\Data_All\\"

    with open('D:\\Allinone\\Programing\\Python\\project\\r_d_challenge\\classify\\2019_output1.csv') as csv_file_handle:

        while True:
            data = csv_file_handle.readline()
            if not data: break

            split_data = data.split(',')
            file_name = os.path.join(folder_path, split_data[2])
            packer_type = split_data[5]
            if 'aspack' in packer_type.lower():
                queue1.put((file_name, 1))
                continue
            if 'upx' in packer_type.lower():
                queue1.put((file_name, 2))
                continue
            if 'fsg' in packer_type.lower():
                queue1.put((file_name, 3))
                continue
    return queue1



if __name__=="__main__":


    queue=mains()


    proc_list =[]
    for _ in range(0 ,5):
        proc =Process(target=packer_check,args=(queue,))
        proc_list.append(proc)
    for proc in proc_list:
        proc.start()
    for proc in proc_list:
        proc.join()
