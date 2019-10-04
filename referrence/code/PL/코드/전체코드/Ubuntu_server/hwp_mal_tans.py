##################################
import olefile
import re
import elasticsearch
import zlib
from operator import eq
import struct 
import sys
import os
import olefile
import zlib
import json
import struct
import binascii
import operator as op
import ssdeep
import tlsh
import shutil
import sys
import tlsh

from io import BytesIO
from datetime import datetime
from datetime import timedelta
from pprint import pprint
#pip install apyio
##################################



class hwp_parser():
    def __init__(self, filename):
        self.filename = filename
        try:
            self.ole = olefile.OleFileIO(filename)
            self.hwp_info = olefile.OleFileIO(filename)
        except:
            #print("NONO")
            return None
        self.list_dir=self.ole.listdir()
        self.ole_dir = ["/".join(i) for i in self.ole.listdir()]
        ## https://github.com/mete0r/pyhwp/blob/82aa03eb3afe450eeb73714f2222765753ceaa6c/pyhwp/hwp5/msoleprops.py#L151
        self.SUMMARY_INFORMATION_PROPERTIES = [
            dict(id=0x02, name='PIDSI_TITLE', title='Title'),
            dict(id=0x03, name='PIDSI_SUBJECT', title='Subject'),
            dict(id=0x04, name='PIDSI_AUTHOR', title='Author'),
            dict(id=0x05, name='PIDSI_KEYWORDS', title='Keywords'),
            dict(id=0x06, name='PIDSI_COMMENTS', title='Comments'),
            dict(id=0x07, name='PIDSI_TEMPLATE', title='Templates'),
            dict(id=0x08, name='PIDSI_LASTAUTHOR', title='Last Saved By'),
            dict(id=0x09, name='PIDSI_REVNUMBER', title='Revision Number'),
            dict(id=0x0a, name='PIDSI_EDITTIME', title='Total Editing Time'),
            dict(id=0x0b, name='PIDSI_LASTPRINTED', title='Last Printed'),
            dict(id=0x0c, name='PIDSI_CREATE_DTM', title='Create Time/Data'),
            dict(id=0x0d, name='PIDSI_LASTSAVE_DTM', title='Last saved Time/Data'),
            dict(id=0x0e, name='PIDSI_PAGECOUNT', title='Number of Pages'),
            dict(id=0x0f, name='PIDSI_WORDCOUNT', title='Number of Words'),
            dict(id=0x10, name='PIDSI_CHARCOUNT', title='Number of Characters'),
            dict(id=0x11, name='PIDSI_THUMBNAIL', title='Thumbnail'),
            dict(id=0x12, name='PIDSI_APPNAME', title='Name of Creating Application'),
            dict(id=0x13, name='PIDSI_SECURITY', title='Security'),
        ]
    
    def xorkey_detect(self):
        file_ssdeep_hash_list=[]
        strings_ssdeep_hash=[]
        
        xor_key_re=re.compile('<\w{4,8}>')
        shellcode_re=re.compile('<(\w+)>')
        for stream in self.list_dir:
            if len(stream)>1:
                ###POST Scrit 언어로 되있을 시###
                if 'PS' in stream[1].upper():
                    post_script_data=self.hwp_info.openstream('BinData/'+stream[1]).read()
                    post_script_decompress_data = zlib.decompress(post_script_data,-15)
                    ###PS 암호화 키 존재 시 ###
                    if len(xor_key_re.findall(str(post_script_decompress_data)))>0:
                        xorkey=xor_key_re.findall(str(post_script_decompress_data))[0].replace('<','').replace('>','')
                        return xorkey
        return None

    def extract_data(self, name):
        stream = self.ole.openstream(name)
        data = stream.read()
        if any(i in name for i in ("BinData", "BodyText", "Scripts")):
            return zlib.decompress(data,-15)
        else:
            return data

    def FILETIME_to_datetime(self, value):
        return (datetime(1601, 1, 1, 0, 0, 0) + timedelta(microseconds=value / 10)).strftime("%Y-%m-%d %H:%M:%S.%f")

    def HwpSummaryInformation(self, data):
        info_data = []
        property_data = []
        return_data = []

        start_offset = 0x2c
        data_size_offset = struct.unpack("<L",data[start_offset:start_offset+4])[0]
        data_size = struct.unpack("<L",data[data_size_offset:data_size_offset+4])[0]
        property_count = struct.unpack("<L",data[data_size_offset+4:data_size_offset+8])[0]

        start_offset = data_size_offset + 8
        
        for i in range(property_count):
            property_ID = struct.unpack("<L",data[start_offset:start_offset+4])[0]
            unknown_data = struct.unpack("<L",data[start_offset+4:start_offset+8])[0]
            property_data.append({"property_ID":property_ID, "unknown_data":unknown_data})
            start_offset = start_offset + 8

        data = data[start_offset:]
        
        start_offset = 0x0
        for i in range(property_count):
            if data[start_offset:start_offset+4] == b"\x1f\x00\x00\x00":
                size = struct.unpack("<L",data[start_offset+4:start_offset+8])[0] * 2
                result = data[start_offset+8:start_offset+8+size]
                info_data.append(result.decode("utf-16-le"))

                start_offset = start_offset + 8 + size
                if data[start_offset:start_offset+2] == b"\x00\x00":
                    start_offset += 2

            elif data[start_offset:start_offset+4] == b"\x40\x00\x00\x00":
                date = struct.unpack("<Q", data[start_offset+4:start_offset+12])[0]
                start_offset = start_offset + 12
                info_data.append(self.FILETIME_to_datetime(date))


        for i in range(len(info_data)):
            for information in self.SUMMARY_INFORMATION_PROPERTIES:
                if information['id'] == property_data[i]['property_ID']:
                    return_data.append({"property_ID":property_data[i]['property_ID'], 
                                        "title":information['title'], 
                                        "name":information['name'], 
                                        "data":info_data[i],
                                        "unknown_data":property_data[i]['unknown_data']})
                    continue

        return return_data

    def run(self):
        dic_result = {}
        #print("[*] Filename : {}".format(self.filename))
        #print("[*] ole dir : {}\n".format(self.ole_dir))
        result_list=[]
        for name in self.ole_dir:
            if "hwpsummaryinformation" in name.lower():
                data = self.extract_data(name)
                result = self.HwpSummaryInformation(data)
                result_list.append(result)
                
            if ".ps" in name.lower() or ".eps" in name.lower():
                pass
        try:
            for i in range(0,len(result_list[0])):
                dic_result[result_list[0][i]['title']] = result_list[0][i]['data']
        except:
            return None

        return dic_result
###########################################################################################

def exstrings(FILENAME,regex=None):
    EXSTRINGS_RESULT_LIST=[]
    fp=open(FILENAME,'rb')
    bindata = str(fp.read())
    if regex is None:
        regex = re.compile("[\w\~\!\@\#\$\%\^\&\*\(\)\-_=\+ \/\.\,\?\s]{4,}")
        
        BINDATA_RESULT = regex.findall(bindata)
    else:
        regex = re.compile(regex)
    for BINDATA in BINDATA_RESULT:
        if len(BINDATA)>3000:
            continue
        try:
            regex2=re.compile('([x\d]+)|([\D]+)')
            
            BINDATA_REGEX2=regex2.search(BINDATA)
            if BINDATA_REGEX2.group(1)==None:
                if len(BINDATA_REGEX2.group(2))>6:
                    if BINDATA_REGEX2.group(2) in importlists:
                        continue
                    EXSTRINGS_RESULT_LIST.append(BINDATA_REGEX2.group(2).upper())
            elif BINDATA_REGEX2.group(1)!=None:
                regex2=re.compile('([x\d]+)([\D]+)')
                BINDATA_REGEX2=regex2.search(BINDATA)
                if len(BINDATA_REGEX2.group(2))>6:
                    if BINDATA_REGEX2.group(2) in importlists:
                        continue
                    EXSTRINGS_RESULT_LIST.append(BINDATA_REGEX2.group(2).upper())
        except:
            continue
    fp.close()
    return EXSTRINGS_RESULT_LIST


def classify(hwp_sample_full_path,author,last_save,XOR_KEY):
    EXSTRINGS_RESULT_LIST=exstrings(hwp_sample_full_path)
    base_name=os.path.basename(hwp_sample_full_path)
    
    
    
    
    
    
    #Scacruft
    scar_new_path="/home/bob/HWP_Malware_sample/scarcuft"
    Scacruft_Author_list=['TAMES','LION','SEIKO','DOCPRINT','YADEX','MEDIAFIRE','PCLOUD','2NDBD', 'yadex', 'mediafire' ,'pcloud','2ndBD']
    if author in Scacruft_Author_list or last_save in Scacruft_Author_list:
        print("Scacruft")
        print("\tFile Hash : {}".format(hwp_sample_full_path))
        print("\tLAST Saved by : {}".format(last_save))
        print("\tAuthor : {}\n".format(author))
        shutil.move(hwp_sample_full_path,os.path.join(scar_new_path,base_name))
        return
    for Scacruft_strings in Scacruft_Author_list:
        if Scacruft_strings.upper() in EXSTRINGS_RESULT_LIST:
            print("Scacruft")
            print("\tFile Hash : {}".format(hwp_sample_full_path))
            print("\tStrings : {}".format(Scacruft_strings))
            print("\tLAST Saved by : {}".format(last_save))
            print("\tAuthor : {}\n".format(author))
            shutil.move(hwp_sample_full_path,os.path.join(scar_new_path,base_name))
            return
            
            
            
            
            
            

    #Kimsuky
    kimsuky_path="/home/bob/HWP_Malware_sample/kimsuky"
    Kimsuky_Author_list=['burari','JOHN','MND','TEST','MOFA','MNDUSER','ZYX.DLL','zyx.dll','황재오','임병철','LAZY','BURARI','JOYBERTM','fontchk.jse','FONTCHK.JSE','CORE.DLL','HIMTRAYICON','UAC_dll','ghkdwodh']
    if author in Kimsuky_Author_list or last_save in Kimsuky_Author_list:
        print("Kimsuky")
        print("\tFile Hash : {}".format(hwp_sample_full_path))
        print("\tLAST Saved by : {}".format(last_save))
        print("\tAuthor : {}\n".format(author))
        shutil.move(hwp_sample_full_path,os.path.join(kimsuky_path,base_name))
        return
    for Kimsuky_strings in Kimsuky_Author_list:
        if Kimsuky_strings.upper() in EXSTRINGS_RESULT_LIST:
            print("Kimsuky")
            print("\tFile Hash : {}".format(hwp_sample_full_path))
            print("\tStrings : {}".format(Kimsuky_strings))
            print("\tLAST Saved by : {}".format(last_save))
            print("\tAuthor : {}\n".format(author))
            shutil.move(hwp_sample_full_path,os.path.join(kimsuky_path,base_name))
            return




        
    #Bluenoroff
    blue_path="/home/bob/HWP_Malware_sample/bluenoroff"
    Bluenoroff_Author_list=['ALOSHA', 'TATIANA', 'TIGER','YINZI', 'YAOSHI', 'YIMA','JAE','Happy','JIKPURID','KDS']
    Bluenoroff_XOR_KEY_list=['384E8B45',
                            'EB3BB378',
                            '775D1172',
                            'B45CD16C',
                            'BE2D3A7C',
                            'ED01AC2C',
                            'CC31767A',
                            '78684245',
                            'A64A06F7',
                            'C5604F7E',
                            'B410AAB2',
                            'D6AA059B',
                            'B46A4998',
                            'DACD3C87',
                            'A3E6E7BB',
                            'B889008C',
                            '76759264'
                            ]
    if author in Bluenoroff_Author_list or last_save in Bluenoroff_Author_list:
        print("Bluenoroff")
        print("\tFile Hash : {}".format(hwp_sample_full_path))
        print("\tLAST Saved by : {}".format(last_save))
        print("\tAuthor : {}\n".format(author))
        shutil.move(hwp_sample_full_path,os.path.join(blue_path,base_name))
        return
    for Blue_strings in Bluenoroff_Author_list:
        if Blue_strings.upper() in EXSTRINGS_RESULT_LIST:
            print("Bluenoroff")
            print("\tFile Hash : {}".format(hwp_sample_full_path))
            print("\tStrings : {}".format(Blue_strings))
            print("\tLAST Saved by : {}".format(last_save))
            print("\tAuthor : {}\n".format(author))
            shutil.move(hwp_sample_full_path,os.path.join(blue_path,base_name))
            return
    if XOR_KEY in Bluenoroff_XOR_KEY_list:
        print("Bluenoroff")
        print("\tFile Hash : {}".format(hwp_sample_full_path))
        print("\tLAST Saved by : {}".format(last_save))
        print("\tAuthor : {}".format(author))
        print("\tXOR_KEY : {}\n".format(XOR_KEY))
        shutil.move(hwp_sample_full_path,os.path.join(blue_path,base_name))
        return
    
    
    

def ssdeep_tlsh_compare(target_sample,group_names=None):
    with open(target_sample, 'rb') as f:
        data = f.read()
        target_sample_tlsh = tlsh.hash(data)
        f.close()
    target_sample_ssdeep = ssdeep.hash_from_file(target_sample)
    target_basename=os.path.basename(target_sample)
    
    hwp_malware_sample_path="/home/bob/HWP_Malware_sample"
    for samples in os.listdir(hwp_malware_sample_path):
        #같은 파일 예외처리
        if samples in os.path.basename(target_sample):
            continue
        
        hwp_sample_full_path=os.path.join(hwp_malware_sample_path,samples)
        try:
            with open(hwp_sample_full_path, 'rb') as f:
                data = f.read()
                hwp_sample_tlsh = tlsh.hash(data)
                f.close()
        except:
            continue
        hwp_sample_ssdeep = ssdeep.hash_from_file(hwp_sample_full_path)
        hwp_sample_basename=os.path.basename(hwp_sample_full_path)
        
        #tlsh compare
        tlsh_result=tlsh.diff(target_sample_tlsh, hwp_sample_tlsh)
        if tlsh_result<20:
            if group_names==None:
                print("Non Groups Names : {}".format(target_sample))
            else:
                print("Groups Names : {}".format(group_names))
            print("\ttlsh_result Compare : {}".format(tlsh_result))
            print("\t\tTarget Samples : {} ".format(target_basename))
            print("\t\tHwp Samples : {} ".format(hwp_sample_basename))
            '''
            try:
                if group_names=='bluenoroff':
                    blue_path="/home/bob/HWP_Malware_sample/bluenoroff"
                    shutil.move(hwp_sample_full_path,os.path.join(blue_path,samples))
                elif group_names=='kimsuky':
                    kimsuky_path="/home/bob/HWP_Malware_sample/kimsuky"
                    shutil.move(hwp_sample_full_path,os.path.join(kimsuky_path,samples))
                elif group_names=='scarcuft':
                    scar_new_path="/home/bob/HWP_Malware_sample/scarcuft"
                    shutil.move(hwp_sample_full_path,os.path.join(scar_new_path,samples))
                elif group_names==None:
                    #폴더가 이미 존재할 시 폴더를 만들어서 비교
                    if os.path.exists(os.path.join(hwp_malware_sample_path,target_basename))!=True:
                        os.makedirs(os.path.join(hwp_malware_sample_path,target_basename))
                        shutil.move(hwp_sample_full_path,os.path.join(hwp_malware_sample_path,target_basename))
                        shutil.move(target_sample,os.path.join(hwp_malware_sample_path,target_basename))
                    else:
                        shutil.move(hwp_sample_full_path,os.path.join(hwp_malware_sample_path,target_basename))
            except:
                pass
             '''
        #ssdeep compare
        ssdeep_result=ssdeep.compare(target_sample_ssdeep,hwp_sample_ssdeep)
        if ssdeep_result>86:
            if group_names==None:
                print("Non Groups Names : {}".format(target_sample))
            else:
                print("Groups Names : {}".format(group_names))
            print("\tSSDEEP Compare : {}".format(ssdeep_result))
            print("\t\tTarget Samples : {} ".format(target_basename))
            print("\t\tHwp Samples : {} ".format(hwp_sample_basename))
            
            try:
                if group_names=='bluenoroff':
                    blue_path="/home/bob/HWP_Malware_sample/bluenoroff"
                    shutil.move(hwp_sample_full_path,os.path.join(blue_path,samples))
                elif group_names=='kimsuky':
                    kimsuky_path="/home/bob/HWP_Malware_sample/kimsuky"
                    shutil.move(hwp_sample_full_path,os.path.join(kimsuky_path,samples))
                elif group_names=='scarcuft':
                    scar_new_path="/home/bob/HWP_Malware_sample/scarcuft"
                    shutil.move(hwp_sample_full_path,os.path.join(scar_new_path,samples))
                elif group_names=="NoneGroup1":
                    #폴더가 이미 존재할 시 폴더를 만들어서 비교
                    if os.path.exists(os.path.join(hwp_malware_sample_path,target_basename))!=True:
                        os.makedirs(os.path.join(hwp_malware_sample_path,target_basename))
                        shutil.move(hwp_sample_full_path,os.path.join(hwp_malware_sample_path,target_basename))
                        shutil.move(target_sample,os.path.join(hwp_malware_sample_path,target_basename))
                    else:
                        shutil.move(hwp_sample_full_path,os.path.join(hwp_malware_sample_path,target_basename))
            except:
                pass
            

###########################################################################################


def mains():

    ################SSDEEP TLSH 유사도 부분#########################
    
    hwp_malware_sample_path="/home/bob/HWP_Malware_sample/konni"
    group_names=os.path.basename(hwp_malware_sample_path)
    for sample in os.listdir(hwp_malware_sample_path):
        try:
            hwp_sample_full_path=os.path.join(hwp_malware_sample_path,sample)
            ssdeep_tlsh_compare(hwp_sample_full_path,group_names)
        except:
            continue
    '''
    hwp_malware_sample_path="/home/bob/HWP_Malware_sample/kimsuky"
    group_names=os.path.basename(hwp_malware_sample_path)
    for sample in os.listdir(hwp_malware_sample_path):
        try:
            hwp_sample_full_path=os.path.join(hwp_malware_sample_path,sample)
            ssdeep_tlsh_compare(hwp_sample_full_path,group_names)
        except:
            continue
    '''
    '''
    hwp_malware_sample_path="/home/bob/HWP_Malware_sample/bluenoroff"
    group_names=os.path.basename(hwp_malware_sample_path)
    for sample in os.listdir(hwp_malware_sample_path):
        try:
            hwp_sample_full_path=os.path.join(hwp_malware_sample_path,sample)
            ssdeep_tlsh_compare(hwp_sample_full_path,group_names)
        except:
            continue
    
    
    hwp_malware_sample_path="/home/bob/HWP_Malware_sample/NoneGroup1"
    group_names=os.path.basename(hwp_malware_sample_path)
    for sample in os.listdir(hwp_malware_sample_path):
        try:
            hwp_sample_full_path=os.path.join(hwp_malware_sample_path,sample)
            ssdeep_tlsh_compare(hwp_sample_full_path,group_names)
        except:
            continue
    ################태그, 작성자, xor 키로 찾는 부분#################
    for sample in os.listdir(hwp_malware_sample_path):
        try:
            hwp_sample_full_path=os.path.join(hwp_malware_sample_path,sample)
            HWP_HeaderParser_class = hwp_parser(hwp_sample_full_path)
            Header_Parser_result_dic=HWP_HeaderParser_class.run()
            XOR_KEY=HWP_HeaderParser_class.xorkey_detect()
            
           #print("[*] Filename : {}".format(hwp_sample_full_path))
            last_save=Header_Parser_result_dic['Last Saved By'].upper().replace('\x00','')
            author=Header_Parser_result_dic['Author'].upper().replace('\x00','')
        except:
            continue
    
        classify(hwp_sample_full_path,author,last_save,XOR_KEY)
    
    '''


if __name__ == "__main__":
    mains()