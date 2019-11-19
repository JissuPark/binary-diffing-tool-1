from Main_engine.ML import new_check_pe
import filetype
import csv,os,pefile
import math
import numpy as np
import json
import os
import datetime
from multiprocessing import Process, current_process ,Queue, Pool


class getinfo_pe:


    IMAGE_DOS_HEADER = [
                        "e_cblp",\
                        "e_cp", \
                        "e_cparhdr",\
                        "e_maxalloc",\
                        "e_sp",\
                        "e_lfanew"]

    FILE_HEADER= ["NumberOfSections","CreationYear"] + [ "FH_char" + str(i) for i in range(15)] +\
                 ["Machine", "PointerToSymbolTable","NumberOfSymbols", "SizeOfOptionalHeader", "Characteristics"]

    OPTIONAL_HEADER1 = [
        "MajorLinkerVersion", \
        "MinorLinkerVersion", \
        "SizeOfCode", \
        "SizeOfInitializedData", \
        "SizeOfUninitializedData", \
        "AddressOfEntryPoint", \
        "BaseOfCode", \
        "ImageBase", \
        "SectionAlignment", \
        "FileAlignment", \
        "MajorOperatingSystemVersion", \
        "MinorOperatingSystemVersion", \
        "MajorImageVersion", \
        "MinorImageVersion", \
        "MajorSubsystemVersion", \
        "MinorSubsystemVersion", \
        "SizeOfImage", \
        "SizeOfHeaders", \
        "CheckSum", \
        "Subsystem",\
        "NumberOfRvaAndSizes"]
    OPTIONAL_HEADER_DLL_char = ["OH_DLLchar" + str(i) for i in range(11)]
    OPTIONAL_HEADER2 = [
        "SizeOfStackReserve", \
        "SizeOfStackCommit", \
        "SizeOfHeapReserve", \
        "SizeOfHeapCommit", \
        "LoaderFlags"]  # boolean check for zero or not
    OPTIONAL_HEADER = OPTIONAL_HEADER1 + OPTIONAL_HEADER_DLL_char + OPTIONAL_HEADER2

    SUSPICIOUS_SECTION_COUNT=["sus_sections","non_sus_sections"]
    SECTION_INFO = ["Section_Infos" + str(i) for i in range(21 * 15)]
    SECTION_INFO2 = ["SectionsNb","SectionsMeanEntropy","SectionsMinEntropy","SectionsMaxEntropy",\
                     "SectionsMeanRawsize","SectionsMinRawsize","SectionsMaxRawsize","SectionsMeanVirtualsize",\
                     "SectionsMinVirtualsize","SectionMaxVirtualsize"]

    TLS_Data = ["AddressOfCallBacks", "AddressOfIndex", "Characteristics", "EndAddressOfRawData"]

    STRING_FILE_INFO=["Signature","StrucVersion","FileFlagsMask","FileFlags","Length","FileOS","Version_Type","FileType","FileSubtype","FileDateMS","FileDateLS","ProductVersion","FileVersion"]

    IMPORTS=["ImportsNbDLL","ImportsNb","ImportsNbOrdinal"]

    EXPORTS=["ExportNb"]

    RESOURCE=["ResourcesNb","ResourcesMeanEntropy","ResourcesMinEntropy","ResourcesMaxEntropy",\
              "ResourcesMeanSize","ResourcesMinSize","ResourcesMaxSize"]

    CONFIGURATION_SIZE=["LoadConfigurationSize"]

    PAKCER_TYPE= ["packer","packer_type"]

    FILE_SIZE_16=["FILE_SIZE_16"]

    API_LIST=["API_Infos" + str(i) for i in range(159)]

    CodeSign=['CodeSign']

    Str_2gram=["Str_gram" + str(i) for i in range(118)]

    RichHeader = ["Rich_Infos" + str(i) for i in range(197)]

    Distorms=["opcode_Infos" + str(i) for i in range(77)]

    Size_Label=["size_label" + str(i) for i in range(1)]


    def __init__(self):
        #Train_SET
        #self.input_directory = "D:\\Allinone\\Programing\\Python\\악성코드통합\\Data_All\\"
        #self.output_file = "./"+datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S")+"_outfile.csv"
        #self.label_file = "./labels.txt"

        #predict_SET
        #self.predict_file_path = "D:\\Allinone\\Programing\\Python\\악성코드통합\\R&D_데이터_챌린지_2019"
        #self.file_full_path_list = [os.path.join(self.predict_file_path, sample) for sample in os.listdir(self.predict_file_path)]
        #self.predict_ml_csv_path="./predict.csv"
        pass

    def peature_get_info(self,files,label=0):
        file_base_name=os.path.basename(files)
        result_data=[]

        pe=pefile.PE(files)
        pe_extract=new_check_pe.pe_features()
        dos_header=pe_extract.extract_dos_header(pe)
        file_header=pe_extract.extract_file_header(pe)
        optional_header=pe_extract.extract_optional_header(pe)
        count_suspicious_sections=pe_extract.get_count_suspicious_sections(pe)
        section_info=pe_extract.section_infos(pe)
        section_info2 = pe_extract.section_info2(pe)
        tls_data=pe_extract.get_tls_data(pe)
        file_info=pe_extract.get_fileinfo(pe)
        imports=pe_extract.Import(pe)
        exports=pe_extract.Export(pe)
        resource=pe_extract.Resource(pe)
        configuration_sizes=pe_extract.configuration_size(pe)
        packer_type=pe_extract.check_packer(files)
        file_size_flag = pe_extract.file_size_16(files)
        import_result_list=pe_extract.import_lists(files)
        codesign_flag=pe_extract.extractPKCS7(files)
        if codesign_flag==None:codesign_flag=[0]
        string_data=new_check_pe.exstrings(files)
        RichHeader=new_check_pe.RichHeader_data(files)
        #opcode_histogram=new_check_pe.opcode_info_get(files)
        size_label=new_check_pe.size_label(files)



        result_data+=dos_header
        result_data+=file_header
        result_data+=optional_header
        result_data+=count_suspicious_sections
        result_data+=section_info
        result_data+=section_info2
        result_data+=tls_data
        result_data+=file_info
        result_data+=imports
        result_data+=exports
        result_data+=resource
        result_data+=configuration_sizes
        result_data+=packer_type
        result_data+=file_size_flag
        result_data+=import_result_list
        result_data+=codesign_flag
        result_data +=string_data
        result_data+=RichHeader
        #result_data += opcode_histogram
        result_data += size_label
        result_data+=[label]

        return result_data

    def read_label_file(self):
        dict_label = {}
        label_file_handle = open(self.label_file, 'r', encoding='utf-8')
        while True:
            line_txt = label_file_handle.readline()
            if not line_txt: break
            split_text = line_txt.split('\t')
            dict_label[split_text[0]] = split_text[1]
        return dict_label


    def predict_peature_get_info(self,files):
        file_base_name=os.path.basename(files)

        result_data=[]

        pe=pefile.PE(files)
        pe_extract=new_check_pe.pe_features()
        dos_header=pe_extract.extract_dos_header(pe)
        file_header=pe_extract.extract_file_header(pe)
        optional_header=pe_extract.extract_optional_header(pe)
        count_suspicious_sections=pe_extract.get_count_suspicious_sections(pe)
        section_info=pe_extract.section_infos(pe)
        section_info2 = pe_extract.section_info2(pe)
        tls_data=pe_extract.get_tls_data(pe)
        file_info=pe_extract.get_fileinfo(pe)
        imports=pe_extract.Import(pe)
        exports=pe_extract.Export(pe)
        resource=pe_extract.Resource(pe)
        configuration_sizes=pe_extract.configuration_size(pe)
        packer_type=pe_extract.check_packer(files)
        file_size_flag = pe_extract.file_size_16(files)
        import_result_list=pe_extract.import_lists(files)
        codesign_flag=pe_extract.extractPKCS7(files)
        if codesign_flag==None:codesign_flag=[0]
        string_data=new_check_pe.exstrings(files)
        RichHeader=new_check_pe.RichHeader_data(files)
        #opcode_histogram=new_check_pe.opcode_info_get(files)
        size_label=new_check_pe.size_label(files)

        result_data+=dos_header
        result_data+=file_header
        result_data+=optional_header
        result_data+=count_suspicious_sections
        result_data+=section_info
        result_data+=section_info2
        result_data+=tls_data
        result_data+=file_info
        result_data+=imports
        result_data+=exports
        result_data+=resource
        result_data+=configuration_sizes
        result_data+=packer_type
        result_data+=file_size_flag
        result_data+=import_result_list
        result_data+=codesign_flag
        result_data +=string_data
        result_data+=RichHeader
        #result_data += opcode_histogram
        result_data += size_label

        return result_data

    def predict_write_header_set(self):
        #File PATH
        filepath = self.predict_ml_csv_path

        #CSV Header
        header= ["FileHash"]\
                        +self.IMAGE_DOS_HEADER\
                        + self.FILE_HEADER \
                        + self.OPTIONAL_HEADER\
                        + self.SUSPICIOUS_SECTION_COUNT \
                        + self.SECTION_INFO \
                        +self.SECTION_INFO2 \
                        +self.TLS_Data \
                        + self.STRING_FILE_INFO \
                        + self.IMPORTS \
                        + self.EXPORTS \
                        + self.RESOURCE \
                        + self.CONFIGURATION_SIZE\
                        + self.PAKCER_TYPE\
                        + self.FILE_SIZE_16\
                        +self.API_LIST\
                        +self.CodeSign\
                        +self.Str_2gram\
                        +self.RichHeader \
                        +self.Distorms\
                        +self.Size_Label\


        with open(filepath, 'w+', newline='',encoding='utf-8') as csv_file:

            #CSV Write DATA
            writer = csv.writer(csv_file, delimiter=',')
            writer.writerow(header)

    def predict_queue(self,queue):
        for sample_full_path in self.file_full_path_list:
            queue.put(sample_full_path)

    def predict_create_csv(self,queue):
        while queue.empty() != True:

            if queue.qsize()%1000==0:
                print(queue.qsize())

            sample_full_path=queue.get()
            try:
                input_x_data = self.predict_peature_get_info(sample_full_path)
            except:
                print(os.path.basename(sample_full_path))
                continue
            with open(self.predict_ml_csv_path, 'a', newline='', encoding='utf-8') as csv_file:
                # CSV Write DATA
                writer = csv.writer(csv_file, delimiter=',')
                writer.writerow([os.path.basename(sample_full_path)] +input_x_data)



    def write_header_set(self):
        #File PATH
        filepath = self.output_file

        #CSV Header
        header= self.IMAGE_DOS_HEADER\
                        + self.FILE_HEADER \
                        + self.OPTIONAL_HEADER\
                        + self.SUSPICIOUS_SECTION_COUNT \
                        + self.SECTION_INFO \
                        +self.SECTION_INFO2 \
                        +self.TLS_Data \
                        + self.STRING_FILE_INFO \
                        + self.IMPORTS \
                        + self.EXPORTS \
                        + self.RESOURCE \
                        + self.CONFIGURATION_SIZE\
                        + self.PAKCER_TYPE\
                        + self.FILE_SIZE_16\
                        +self.API_LIST\
                        +self.CodeSign\
                        +self.Str_2gram\
                        +self.RichHeader \
                        +self.Distorms\
                        +self.Size_Label\
                        +["label"]

        with open(filepath, 'w+', newline='',encoding='utf-8') as csv_file:

            #CSV Write DATA
            writer = csv.writer(csv_file, delimiter=',')
            writer.writerow(header)

    def write_csv_data(self,data):
        filepath = self.output_file
        if len(data)!=978:return 0

        with open(filepath, 'a', newline='',encoding='utf-8') as csv_file:

            #CSV Write DATA
            writer = csv.writer(csv_file, delimiter=',')
            writer.writerow(data)
        return 1

    def queue_input_file_path(self,queue):

        dict_label=self.read_label_file()
        for (path, dir, files) in os.walk(self.input_directory):
            for filename in files:
                file_full_path = os.path.join(path, filename)
                try:
                    label = str(dict_label[filename])
                except:
                    print(filename)
                    continue
                queue.put((file_full_path, label))
        '''
        Kaspersky_classfi="D:\\Allinone\\Programing\\Python\\project\\r_d_challenge\\classify\\virus_output.csv"
        with open(Kaspersky_classfi) as csv_file_handle:
            kaspersky_class={'virusname': 2, 'Trojan': 3,'Trojan-Downloader': 4,'Virus': 5,'WebToolbar': 6,'AdWare': 7,'Trojan-Ransom': 8,
                            'HackTool': 9,'Trojan-Spy': 10,'Backdoor': 11,'Packed': 12,'Worm': 13,'DangerousObject': 14,'Trojan-Dropper': 15,
                            'Trojan-Clicker': 16,'Downloader': 17,'Trojan-Proxy': 18,'Trojan-PSW': 19,'Porn-Dialer': 20,'Trojan-Banker': 21,'Trojan-FakeAV': 21,
                            'Trojan-IM': 22,'Trojan-GameThief': 23,'Hoax': 24,'RemoteAdmin': 25,'Trojan-Notifier': 26,'Trojan-DDoS': 27,'Email-Worm': 28,
                            'RiskTool': 29,'Net-Worm': 30,'VirTool': 31,'Constructor': 32,'PSWTool': 33,'P2P-Worm': 34,'Exploit': 35,'Adware': 36,'Monitor': 37,
                            'IM-Flooder': 38,'IM-Worm': 39,'NetTool': 40,'Rootkit': 41,'Email-Flooder': 42,'Flooder': 43,'IRC-Worm': 44,'SMS-Flooder': 45,
                            'Dialer': 46,'DoS': 47,'Porn-Tool':48,'Spoofer': 49}
            kaspersky_dicts={}
            while True:
                data = csv_file_handle.readline()
                if not data:break
                data=data.split(',')
                filename = data[1]
                mal_type = data[2]
                file_type = data[3]
                kaspersky_dicts[filename]=mal_type


        dict_label=self.read_label_file()
        for (path, dir, files) in os.walk(self.input_directory):
            for filename in files:
                file_full_path = os.path.join(path, filename)
                try:
                    label = str(dict_label[filename])
                except:
                    print(filename)
                    continue
                if label=='1':
                    try:
                        label=str(kaspersky_class[kaspersky_dicts[filename]])
                    except KeyError:
                        pass
                queue.put((file_full_path, label))
        '''


    def create_data_set(self,queue):
        while queue.empty() != True:
            file_full_path, label=queue.get()

            if queue.qsize()%1000==0:
                print(queue.qsize())
            #print(os.path.basename(file_full_path))
            try:
                data = self.peature_get_info(file_full_path, label)
                self.write_csv_data(data)
            except:
                print(file_full_path)




if __name__=="__main__":
    '''
    #ML Train
    queue=Queue()
    info_pe_class=getinfo_pe()
    info_pe_class.write_header_set()
    info_pe_class.queue_input_file_path(queue)

    #start Multi Process
    proc_list =[]
    for _ in range(0 ,15):
        proc =Process(target=info_pe_class.create_data_set ,args=(queue,))
        proc_list.append(proc)
    for proc in proc_list:
        proc.start()
    for proc in proc_list:
        proc.join()
    '''

    #ML Prdict
    queue2=Queue()
    info_pe_class=getinfo_pe()
    info_pe_class.predict_queue(queue2)
    #info_pe_class.predict_write_header_set()

    #start Multi Process
    proc_list =[]
    for _ in range(0 ,17):
        proc =Process(target=info_pe_class.predict_create_csv ,args=(queue2,))
        proc_list.append(proc)
    for proc in proc_list:
        proc.start()
    for proc in proc_list:
        proc.join()
