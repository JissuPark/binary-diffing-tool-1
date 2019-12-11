# -*- coding: utf-8 -*-
import yara
import csv
import os


#####################################################
yara_path="Main_engine/Check_Packing/peid.yara"
rules = yara.compile(filepath=yara_path)
result_csv_path="Main_engine/Check_Packing/File_Packer_Type.csv"
result_csv_count_path="Main_engine/Check_Packing/File_Packer_Count.csv"

# yara_path="./peid.yara"
# rules = yara.compile(filepath=yara_path)
# result_csv_path="./File_Packer_Type.csv"
# result_csv_count_path="./File_Packer_Count.csv"
#####################################################




def sample_packer_type_detect(sample_path):
    packer_dict_count={}
    # CSV Write DATA
    with open(result_csv_path, 'w+', newline='', encoding='utf-8') as csv_file:
        count = 1

        read_mal = open(sample_path, "rb")
        read_data = read_mal.read()
        read_mal.close()

        matches_list = rules.match(data=read_data)
        if matches_list == {} :
            return -3
        else:
            try:
                packer_dict_count[matches_list['main'][0]['rule']]+=1
            except:
                packer_dict_count[matches_list['main'][0]['rule']]=0
            writer = csv.writer(csv_file, delimiter=',')
            writer.writerow([sample_path]+[matches_list['main'][0]['rule']])


    # CSV File Count Write DATA
    with open(result_csv_count_path, 'w+', newline='', encoding='utf-8') as csv_file:

        writer = csv.writer(csv_file, delimiter=',')
        for key, values in packer_dict_count.items():
            writer.writerow([key]+[values])

if __name__=="__main__":
    sample_packer_type_detect()