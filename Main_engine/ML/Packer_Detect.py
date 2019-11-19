import yara
import csv
import os


#####################################################
yara_path="./peid.yara"
Sample_dir_Full_path="E:\\sample\\R_D_All_DataSet\\"
rules = yara.compile(filepath=yara_path)

csv_2017="D:\\Allinone\\Programing\\Python\\악성코드통합\\R&D_데이터_챌린지_2017\\KISA-CISC2017-Malware-1st\\"
csv_2018="D:\\Allinone\\Programing\\Python\\악성코드통합\\R&D_데이터_챌린지_2018\\TrainSet\\"
csv_2019="D:\\Allinone\\Programing\\Python\\악성코드통합\\KISA-challenge2019-Malware_trainset\\trainSet\\"

label_file="labels.txt"
#####################################################




def csv_writer(dict_label,sample_list,csv_file_name,year):

    # CSV Write DATA
    result_csv_path="./"+year+"_"+csv_file_name
    with open(result_csv_path, 'w+', newline='', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file, delimiter=',')

        csv_hedaer=["Packer","Malware","No_malware","percent"]
        writer.writerow(csv_hedaer)

        packer_dict_malware_count = {}

        for sample_full_path in sample_list:
            sample_base_name=os.path.basename(sample_full_path)
            #print(sample_full_path)
            try:
                read_mal = open(sample_full_path, "rb")
                read_data = read_mal.read()
                read_mal.close()

                matches_list= rules.match(data=read_data)
            except:
                continue

            if matches_list==[]:continue

            if dict_label[sample_base_name]=='0' :
                print('test')
                for matches in matches_list:
                    try:
                        packer_dict_malware_count[matches][1]+=1
                    except:
                        packer_dict_malware_count[matches]=[0, 0]
                        packer_dict_malware_count[matches][1] += 1

            elif dict_label[sample_base_name]=='1':
                for matches in matches_list:
                    print('test')
                    try:
                        packer_dict_malware_count[matches][0] += 1
                    except:
                        packer_dict_malware_count[matches] = [0, 0]
                        packer_dict_malware_count[matches][0] += 1


        for packer_key in packer_dict_malware_count.keys():
            if packer_dict_malware_count[packer_key][0] ==0:
                percent=[0]
            else:
                percent = [(packer_dict_malware_count[packer_key][0] / sum(packer_dict_malware_count[packer_key])) * 100]
            writer.writerow([packer_key]+ packer_dict_malware_count[packer_key]+percent)

def sample_packer_counting():
    dict_label = {}
    label_file_handle = open(label_file, 'r', encoding='utf-8')
    while True:
        line_txt = label_file_handle.readline()
        if not line_txt: break
        split_text = line_txt.split('\t')
        dict_label[split_text[0]] = split_text[1]
    label_file_handle.close()
    '''
    malware_full_path_list = []
    malware_full_path_list += [os.path.join(csv_2017, malware) for malware in os.listdir(csv_2017)]
    malware_full_path_list += [os.path.join(csv_2018, malware) for malware in os.listdir(csv_2018)]
    malware_full_path_list += [os.path.join(csv_2019, malware) for malware in os.listdir(csv_2019)]

    csv_2017_sample = [os.path.join(csv_2017, malware) for malware in os.listdir(csv_2017)]
    '''
    csv_2018_sample = [os.path.join(csv_2018, malware) for malware in os.listdir(csv_2018)]

    csv_2019_sample = [os.path.join(csv_2019, malware) for malware in os.listdir(csv_2019)]

    #print("full_path_create")
    #csv_writer(dict_label, malware_full_path_list, "packer_all_count.csv", "All")
    #print("2017 create")
    #csv_writer(dict_label, csv_2017_sample, "packer_count_2017.csv", "2017")
    #print("2018 create")
    #csv_writer(dict_label, csv_2018_sample, "packer_count_2018.csv", "2018")
    print("2019 create")
    csv_writer(dict_label, csv_2019_sample, "packer_count_2019.csv", "2019")

#####################################################

'''
def sample_packer_type_detect():
    Sample_List=os.listdir(Sample_dir_Full_path)
    packer_dict_count={}
    # CSV Write DATA
    with open(result_csv_path, 'w+', newline='', encoding='utf-8') as csv_file:
        for sample in Sample_List:
            print(sample)

            sample_full_path=os.path.join(Sample_dir_Full_path,sample)

            read_mal = open(sample_full_path, "rb")
            read_data = read_mal.read()
            read_mal.close()

            matches_list= rules.match(data=read_data)
            if matches_list==[]:continue
            for matches in matches_list:
                print(matches)
                try:
                    packer_dict_count[matches]+=1
                except:
                    packer_dict_count[matches]=0
                matches_list
                writer = csv.writer(csv_file, delimiter=',')
                writer.writerow([sample]+matches_list)
'''

if __name__=="__main__":
    sample_packer_counting()