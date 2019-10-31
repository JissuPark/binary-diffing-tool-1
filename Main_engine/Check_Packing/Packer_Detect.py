import yara
import csv
import os


#####################################################
yara_path="Main_engine/Check_Packing/peid.yara"
Sample_dir_Full_path=r"D:\etc\upx394w\aa"
rules = yara.compile(filepath=yara_path)
result_csv_path="Main_engine/Check_Packing/File_Packer_Type.csv"
result_csv_count_path="Main_engine/Check_Packing/File_Packer_Count.csv"
#####################################################




def sample_packer_type_detect():
    Sample_List=os.listdir(Sample_dir_Full_path)
    packer_dict_count={}
    # CSV Write DATA
    with open(result_csv_path, 'w+', newline='', encoding='utf-8') as csv_file:
        for sample in Sample_List:
            count = 0
            print(sample)

            sample_full_path=os.path.join(Sample_dir_Full_path,sample)

            read_mal = open(sample_full_path, "rb")
            read_data = read_mal.read()
            read_mal.close()

            matches_list = list(rules.match(data=read_data))
            if matches_list == {} : continue
            for matches in matches_list:
                try:
                    packer_dict_count[matches]+=1
                except:
                    packer_dict_count[matches]=0

                writer = csv.writer(csv_file, delimiter=',')
                writer.writerow([sample]+[matches_list['main'][count]['rule']])
                count = count +1

    # CSV File Count Write DATA
    with open(result_csv_count_path, 'w+', newline='', encoding='utf-8') as csv_file:

        writer = csv.writer(csv_file, delimiter=',')
        for key, values in packer_dict_count.items():
            writer.writerow([key]+[values])

if __name__=="__main__":
    sample_packer_type_detect()