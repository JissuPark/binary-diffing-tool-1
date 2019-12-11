import pefile
import re
import csv
import os
from multiprocessing import Process, current_process ,Queue, Pool
from collections import Counter

mutex_file = open('mutex_strings_lists.txt', 'r')
mutex_list = [line[:-1] for line in mutex_file]

mutex_file2 = open('win32api_alphabet.txt', 'r')
mutex_list2 = [line2[:-1] for line2 in mutex_file2]

mutex_file3 = open('win32api_category.txt', 'r')
mutex_list3 = [line3[:-1] for line3 in mutex_file3]

ipaddress_re = re.compile('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
email_re = re.compile('^[a-zA-Z0-9+-_.]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
url_re = re.compile(
    r'^(?:(?:https|ftp|www)://)(?:\S+(?::\S*)?@)?(?:(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,})))(?::\d{2,5})?(?:/[^\s]*)?$')

mutex1 = re.compile("[@]")
mutex2 = re.compile("[?]")
mutex3 = re.compile("[=]")
mutex4 = re.compile("[\w]")
mutex5 = re.compile("[\W]")




def exstrings(queue,regex=None):
    string_dics = {}
    while queue.empty() != True:
        FILENAME = queue.get()
        print(FILENAME)

        try:
            importlists=[]

            PF = pefile.PE(FILENAME)

            for entry in PF.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    importlists.append(imp.name.decode())
            PF.close()
        except:continue

        fp = open(FILENAME, 'rb')
        bindata = fp.read()
        bindata=str(bindata )
        fp.close()

        if regex is None:
            regex = re.compile("[\w\~\!\@\#\$\%\^\&\*\(\)\-_=\+ \/\.\,\?\s]{4,}")
            BINDATA_RESULT = regex.findall(bindata)

        for BINDATA in BINDATA_RESULT:
            if len(BINDATA) > 3000:
                continue

            regex2 = re.compile('([x\d]+)|([\D]+)')

            BINDATA_REGEX2 = regex2.search(BINDATA)
            if BINDATA_REGEX2.group(1) == None:
                if len(BINDATA_REGEX2.group(2)) > 6:
                    strings_=BINDATA_REGEX2.group(2)[:-1]
                    if BINDATA_REGEX2.group(2) in importlists or BINDATA_REGEX2.group(2)[:-1] in importlists:
                        continue

                    for index in range(len(strings_) - 4 + 1):
                        join_str = strings_[index:index + 4]
                        #if join_str in string_dics.keys():
                        try:
                            string_dics[join_str] += 1
                        except:
                            string_dics[join_str] = 1



            elif BINDATA_REGEX2.group(1) != None:
                regex2 = re.compile('([x\d]+)([\D]+)')
                BINDATA_REGEX2 = regex2.search(BINDATA)
                if BINDATA_REGEX2==None:continue
                if len(BINDATA_REGEX2.group(2))>6:
                    strings_=BINDATA_REGEX2.group(2)[:-1]
                    if BINDATA_REGEX2.group(2) in importlists or BINDATA_REGEX2.group(2)[:-1] in importlists:
                        continue

                    for index in range(len(strings_) - 4 + 1):
                        join_str = strings_[index:index + 4]
                        #if join_str in string_dics.keys():
                        try:
                            string_dics[join_str] += 1
                        except:
                            string_dics[join_str] = 1

    return string_dics




if __name__=="__main__":
    input_directory = "D:\\Allinone\\Programing\\Python\\악성코드통합\\KISA-challenge2019-Malware_trainset\\trainSet\\"
    folder_path = "D:\\Allinone\\Programing\\Python\\악성코드통합\\Data_preprocessing\\unpacked\\"
    csv_file_path="./4gram.csv"
    label_file = "./labels.txt"

    dict_label = {}
    label_file_handle = open(label_file, 'r', encoding='utf-8')
    while True:
        line_txt = label_file_handle.readline()
        if not line_txt: break
        split_text = line_txt.split('\t')
        dict_label[split_text[0]] = split_text[1]

    queue=Queue()
    sample_full_path_list = [os.path.join(folder_path, sample) for sample in os.listdir(folder_path)]
    sample_full_path_list+=[os.path.join(input_directory,sample) for sample in os.listdir(input_directory)]
    for index,sample_full_path in enumerate(sample_full_path_list):
        if  dict_label[os.path.basename(sample_full_path)]=="1":continue
        queue.put(sample_full_path)



    #start Multi Process
    string_dics=exstrings(queue)
    print("End Processing")



    with open(csv_file_path, 'a', newline='', encoding='utf-8') as csv_file:
        # CSV Write DATA
        writer = csv.writer(csv_file, delimiter=',')
        header=["4gram","count"]
        writer.writerow(header)
        for key in string_dics.keys():
            writer.writerow([key]+[str(string_dics[key])])