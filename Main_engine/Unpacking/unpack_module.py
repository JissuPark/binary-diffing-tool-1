#-*-coding: utf-8
import hashlib
import os
import sys
import threading
import shutil
import time

import subprocess
import math, array
import pefile
from multiprocessing import Process, current_process ,Queue, Pool

from yara import rules


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

yara_path="Main_engine/Unpacking/peid.yara"

# yara_path="./peid.yara"



def packer_check(queue, pack_path, unpack_path):
    # pack_path = C:\malware\unpack_exe\packed
    # unpack_path = C:\malware\unpack_exe\unpacked

    while queue.empty() != True:
        sample_path = queue.get()

        print(sample_path)

        read_mal = open(sample_path, "rb")
        read_data = read_mal.read()
        read_mal.close()

        matches_list = rules.match(data=read_data)

        sample_basename = os.path.basename(sample_path)
        sample_unpack_path = os.path.join(unpack_path, sample_basename)

        yara_match_result = ""

        flag=0
        if matches_list == {}:
            # matches_list 딕셔너리가 비어있단 소리는 야라룰에 매칭되는 게 없다는 뜻이고
            # 그 의미는 2가지로 나뉨
            # 1. 알려지지 않은 패커로 패킹됨
            # 2. 패킹이 안된 파일임

            try:
                pe = pefile.PE(sample_path)
                # pe_entropy = get_file_entropy(sample_path)
                # print(pe_entropy[1])
                # if pe_entropy[1] > 6.3:
                #     flag = 1

                for section in pe.sections:
                    if section.get_entropy() > 6.3 :
                        # 1. 알려지지 않은 패커로 패킹됨
                        flag = 1
                        print('--------------------------------------')


                if flag==1:
                    print('--------------------------------------')
                    unknown_sample_path = os.path.join(pack_path, 'unknown', sample_basename)
                    unknown_folder_path = os.path.join(pack_path, 'unknown')
                    if not (os.path.isdir(unknown_folder_path)): os.makedirs(unknown_folder_path)
                    pe.close()
                    shutil.copy(sample_path, unknown_sample_path)
                    #os.remove(sample_path)
                    continue
                else:
                    # 2. 패킹이 안된 파일임
                    print('--------------------------------------')
                    pe.close()
                    shutil.copy(sample_path, sample_unpack_path)
                    #os.remove(sample_path)
                    continue
            except:
                print('asdjfksdfshfdfgdf')
                unknown_sample_path = os.path.join(pack_path, 'unknown', sample_basename)
                unknown_folder_path = os.path.join(pack_path, 'unknown')
                if not (os.path.isdir(unknown_folder_path)): os.makedirs(unknown_folder_path)
                shutil.copy(sample_path, unknown_sample_path)

        else:
            #yara_match_result += str(matches_list['main'][0]['rule']).lower()+' '
            yara_match_result = str(matches_list['main'][0]['rule']).lower()
            print(yara_match_result)
            print('=============================================')

        File_Data = str(open(sample_path, 'rb').read(0x300)).lower()



        if 'fsg' in File_Data or 'fsg' in yara_match_result:
            print("FSG")
            Unpacks_sub_process(sample_path, 1, sample_unpack_path)
            #os.remove(sample_path)
            continue

        elif 'upx' in yara_match_result:
            print("UPX")
            Unpacks_sub_process(sample_path, 2, sample_unpack_path, pack_path, sample_basename)
            #os.remove(sample_path)
            continue
        elif 'aspack' in yara_match_result:
            print("ASPACK")
            Unpacks_sub_process(sample_path, 3, sample_unpack_path)
            #os.remove(sample_path)
            continue

        else:
            yara_tag=os.path.join(pack_path, yara_match_result)[:-1]
            print(yara_tag)
            if not (os.path.isdir(yara_tag)): os.makedirs(yara_tag)
            yara_tag_sample_path=os.path.join(yara_tag,sample_basename)
            print(yara_tag_sample_path)
            shutil.copy(sample_path, yara_tag_sample_path)
            #os.remove(sample_path)
            print('aaaaaaaaaaaaaa')
            continue

    return



def Unpacks_sub_process(sample_path, flags, sample_unpack_path, pack_path, sample_basename):

    if flags==1:
        process_flag = subprocess.Popen(["MNM_Unpacker.exe", "a", sample_path], shell=True).wait()
        time.sleep(2)
        if process_flag != 0:
            print("Process Not Run")
            mnm_error = os.path.join(pack_path, 'MNM')[:-1]
            if not (os.path.isdir(mnm_error)): os.makedirs(mnm_error)
            mnm_tag_sample_path = os.path.join(mnm_error, sample_basename)
            shutil.copy(sample_path, mnm_tag_sample_path)
            return

        # if os.path.isfile(sample_path + "_"):
        #     shutil.move(sample_path + "_", sample_unpack_path)
        #     #os.remove(sample_path + "_")
        #     return


    elif flags==2:
        process_flag = subprocess.Popen(["upx.exe", "-d", sample_path], shell=True).wait()
        print(sample_path)
        print(process_flag)
        time.sleep(2)
        if process_flag != 0:
            upx_error = os.path.join(pack_path, 'unknownn')[:-1]
            print(upx_error)
            if not (os.path.isdir(upx_error)): os.makedirs(upx_error)
            upx_tag_sample_path = os.path.join(upx_error, sample_basename)
            shutil.copy(sample_path, upx_tag_sample_path)
            return


    elif flags==3:
        process_flag = subprocess.Popen(["MNM_Unpacker.exe", "f", sample_path], shell=True).wait()
        if process_flag == 1:
            print("Process Not Run")
            mnm3_error = os.path.join(pack_path, 'unknownn')[:-1]
            if not (os.path.isdir(mnm3_error)): os.makedirs(mnm3_error)
            mnm3_tag_sample_path = os.path.join(mnm3_error, sample_basename)
            shutil.copy(sample_path, mnm3_tag_sample_path)
            return

        # time.sleep(2)
        # if os.path.isfile(sample_path + "_"):
        #     shutil.copy(sample_path+"_", sample_unpack_path)
        #     #os.remove(sample_path+"_")
        #     return


def mains(sample_folder_path):
    queue=Queue()
    for sample in os.listdir(sample_folder_path):
        sample_Full_Path = os.path.join(sample_folder_path, sample)
        queue.put(sample_Full_Path)
    return queue


if __name__=="__main__":

    sample_folder_path = r"C:\malware\mid_GandCrab_exe"
    save_folder_path = r"C:\malware\packing_info"
    pack_path = os.path.join(save_folder_path,'packed')
    unpack_path = os.path.join(save_folder_path,'unpacked')
    if not (os.path.isdir(save_folder_path)): os.makedirs(save_folder_path)
    if not (os.path.isdir(pack_path)): os.makedirs(pack_path)
    if not (os.path.isdir(unpack_path)): os.makedirs(unpack_path)

    queue=mains(sample_folder_path)
    #start Multi Process
    #packer_check(queue, pack_path, unpack_path)

    proc_list =[]
    for _ in range(0, 5):
        proc = Process(target=packer_check, args=(queue, pack_path, unpack_path,))
        proc_list.append(proc)
    for proc in proc_list:
        proc.start()
    for proc in proc_list:
        proc.join()
