#########reference########################
#http://cleancode-ws.tistory.com/81
#https://github.com/hallazzang/ole-py
#https://github.com/hallazzang/hwp5-table-extractor/wiki/Hwp-%ED%8C%8C%EC%9D%BC%EC%9D%98-%EA%B5%AC%EC%A1%B0
#https://gist.github.com/hy00un/25144d459d200133a7b40e60997e518b
#http://www.reversenote.info/ole-parser-python/
##API View
#https://olefile.readthedocs.io/en/latest/Howto.html
##################################

###########HWP 헤더 구조#########
'''
Hwp File/
├───FileHeader
├───DocInfo
├───BodyText/
│   ├───Section0
│   ├───Section1
│   └───...
├───\005HwpSummaryInformation
├───BinData/
│   ├───BinaryData0
│   ├─── BinaryData1
│   └─── ... [EPS 취약점]
├───PrvText
├───PrvImage
├───DocOptions/
│   ├───_LinkDoc
│   ├───DrmLicense
│   └───...
│   Scripts/        
│   ├───DefaultJScript
│   ├───JScriptVersion
│   └───...
│   XMLTemplate/
│   ├───Schema
│   ├───Instance
│   └───...
└───DocHistory/
    ├───VersionLog0
    ├───VersionLog1
    └───...
'''

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

from io import BytesIO
from datetime import datetime
from datetime import timedelta
from pprint import pprint
import ElasticQueryMaster
import hashlib
#pip install apyio
##################################

##공식 API 사이트##
#https://olefile.readthedocs.io/en/latest/Howto.html


class hwp_parser():
    def __init__(self, filename):
        self.filename = filename
        self.ole = olefile.OleFileIO(filename)
        self.ole_dir = ["/".join(i) for i in self.ole.listdir()]
        ## https://github.com/mete0r/pyhwp/blob/82aa03eb3afe450eeb73714f2222765753ceaa6c/pyhwp/hwp5/msoleprops.py#L151
        self.SUMMARY_INFORMATION_PROPERTIES = [
            dict(id=0x02, name='PIDSI_TITLE', title='Title'),
            dict(id=0x03, name='PIDSI_SUBJECT', title='Subject'),
            dict(id=0x04, name='PIDSI_AUTHOR', title='Author'),
            dict(id=0x05, name='PIDSI_KEYWORDS', title='Keywords'),
            dict(id=0x06, name='PIDSI_COMMENTS', title='Comments'),
            dict(id=0x07, name='PIDSI_TEMPLATE', title='Templates'),
            dict(id=0x08, name='PIDSI_LASTAUTHOR', title='Last_Saved_By'),
            dict(id=0x09, name='PIDSI_REVNUMBER', title='Revision_Number'),
            dict(id=0x0a, name='PIDSI_EDITTIME', title='Total Editing Time'),
            dict(id=0x0b, name='PIDSI_LASTPRINTED', title='Last_Printed'),
            dict(id=0x0c, name='PIDSI_CREATE_DTM', title='Create_Time_Data'),
            dict(id=0x0d, name='PIDSI_LASTSAVE_DTM', title='Last_saved_Time_Data'),
            dict(id=0x0e, name='PIDSI_PAGECOUNT', title='Number of Pages'),
            dict(id=0x0f, name='PIDSI_WORDCOUNT', title='Number of Words'),
            dict(id=0x10, name='PIDSI_CHARCOUNT', title='Number of Characters'),
            dict(id=0x11, name='PIDSI_THUMBNAIL', title='Thumbnail'),
            dict(id=0x12, name='PIDSI_APPNAME', title='Name of Creating Application'),
            dict(id=0x13, name='PIDSI_SECURITY', title='Security'),
        ]

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
        print("[*] Filename : {}".format(self.filename))
        #print("[*] ole dir : {}\n".format(self.ole_dir))
        result_list=[]
        for name in self.ole_dir:
            if "hwpsummaryinformation" in name.lower():
                data = self.extract_data(name)
                result = self.HwpSummaryInformation(data)
                result_list.append(result)
                
            if ".ps" in name.lower() or ".eps" in name.lower():
                pass
        for i in range(0,len(result_list[0])):
            dic_result[result_list[0][i]['title']] = result_list[0][i]['data']

        return dic_result
###########################################################################################
###########################################################################################
'''
HWP 정리
1. OLE
    1) 내부에 MZ 파일 존재하는 경우
    2) POST SCRIPT 문자열 파싱하는 경우

2. PS(EPS)
    1) 내부에 MZ 파일이 존재하는 경우 추출 후 유사도 분석
    2) XOR, 쉘코드가 존재하여 디코딩이 가능한 경우는 쉘코드 디코딩 후 유사도 분석 + 사용된 스크립트를 기준으로 유사도 분석
    3) 인코딩된 쉘코드만 존재하고 디코딩이 불가능한 경우는 사용된 스크립트를 기준으로 유사도 분석
    
3. Macro
    1) 기존 Default Macro와 형태가 다를 경우 
    2) 해당 스크립트에 IP, Domain이 존재할 경우 
'''


def getHash(path):
    blocksize=65536
    afile = open(path, 'rb')
    hasher = hashlib.sha256()
    buf = afile.read(blocksize)
    while len(buf) > 0:
        hasher.update(buf)
        buf = afile.read(blocksize)
    afile.close()
    return hasher.hexdigest()

class Malware_detect:

    Regular_IP = '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    Regular_email ='^[\\w!#$%&’*+/=?\`{|}~^-]+(?:\\.[!#$%&’*+/=?\`{|}~^-])+)*@(?:[A-Z0-9-]+\\.)+[A-z]{2,6}$'
    Regular_url = '^(file|gopher|news|nntp|telnet|https?|ftps?|sftp):\/\/([a-z0-9-]+\.)+[a-z0-9]{2,4}.*$'

    def __init__(self,FilePath):
        self.macro_source = []
        self.variable_source = [] 
        self.FilePath=FilePath
    
        self.hwp_info = olefile.OleFileIO(self.FilePath)
        self.list_dir=self.hwp_info.listdir()
        
    def detect_PostScript(self):
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
                        #print(xorkey)
                        binary_encode = str(post_script_decompress_data.hex())[str(post_script_decompress_data.hex()).find("2065786563")+12:]
                        binary_code = ""
                        for i in range(0,len(binary_encode),len(xorkey)):
                            binary_code += binary_encode[i:i+len(xorkey)]
                            if(len(binary_encode) <= i+len(xorkey)):
                                break
                            binary_code += " "
                        binary_code = binary_code.split(" ")
                    
                        f = open(os.path.basename(self.FilePath)+stream[1],"wb")
                        final_binary = ""
                        for i in binary_code:
                            binary_decode = (int(i,16) ^ int(xorkey,16))
                            final_binary += '{:08x}'.format(binary_decode)
                        f.write(bytearray.fromhex(final_binary))
                        f.close()
                        
                        file_ssdeep_hash=ssdeep.hash_from_file(os.path.basename(self.FilePath)+stream[1])
                        file_ssdeep_hash_list.append(file_ssdeep_hash)
                        
                        


                    #MZ가 그대로 노출되었을 경우
                    elif post_script_decompress_data.hex().find("4d5a90")!=-1:
                        print("MZ Detect")
                        binary_encode=str(post_script_decompress_data.hex())[str(post_script_decompress_data.hex()).find("4d5a90"):]
                        f = open(os.path.basename(self.FilePath)+stream[1],"wb")
                        f.write(bytearray.fromhex(binary_encode))
                        f.close()
                        file_ssdeep_hash=ssdeep.hash_from_file(os.path.basename(self.FilePath)+stream[1])
                        file_ssdeep_hash_list.append(file_ssdeep_hash)
                    
                    
                    ##MZ가 스트링 형태로 그대로 존재할 시##
                    elif post_script_decompress_data.hex().find("346435613930")!=-1:
                        print("MZ Detect")
                        detect_point=str(post_script_decompress_data.hex()).find("346435613930")
                        binary_encode=str(post_script_decompress_data.hex())[detect_point:]
                        binary_encode=binascii.unhexlify(str(binary_encode))
                        binary_encode=binascii.unhexlify(str(binary_encode.decode()))
                        f = open(os.path.basename(self.FilePath)+stream[1],"wb")
                        f.write(binary_encode)
                        f.close()
                        file_ssdeep_hash=ssdeep.hash_from_file(os.path.basename(self.FilePath)+stream[1])
                        file_ssdeep_hash_list.append(file_ssdeep_hash)
                    
                    # 인코딩된 쉘코드만 존재하고 디코딩이 불가능한 경우는 사용된 스크립트를 기준으로 유사도 분석
                    else:
                        print("Extract Strings PS")
                        DEF_RE=re.compile('def(.*)def.*$')
                        DIM_RE=re.compile('DIM+\W[\w]+')
                        DIM_RE2=re.compile('DIM+\W[\w]+,\W[\w]+')
                        SET_RE=re.compile('SET\W\w+\W+=\W+\w+\([\W\w+]\w+\W\w+\W\)')
                        SET_RE2=re.compile( 'SET\W\w+\W+=\W+\w+\([\W\w+]\w+\W\w+\W\)')
                        private_re=re.compile('private[\W\w]+End [Subfunction]+')
                        path_re=re.compile('[a-z,A-Z]:[\\\w.\w]+')
                        path_re2=re.compile('[\\\\w]+[.\w]+')
                        ipaddress_re=re.compile('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
                        email_re=re.compile('^[a-zA-Z0-9+-_.]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
                        url_re=re.compile(r'^(?:(?:https|ftp|www)://)(?:\S+(?::\S*)?@)?(?:(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,})))(?::\d{2,5})?(?:/[^\s]*)?$')

                        binary_encode=str(post_script_decompress_data.decode())
                        result=''.join(DIM_RE.findall(binary_encode))
                        result=result+''.join(DEF_RE.findall(binary_encode))
                        result=result+''.join(DIM_RE2.findall(binary_encode))
                        result=result+''.join(SET_RE.findall(binary_encode))
                        result=result+''.join(SET_RE2.findall(binary_encode))
                        result=result+''.join(private_re.findall(binary_encode))
                        result=result+''.join(ipaddress_re.findall(binary_encode))
                        result=result+''.join(url_re.findall(binary_encode))
                        result=result+''.join(email_re.findall(binary_encode))
                        
                        for path_result in path_re.findall(binary_encode):
                            path_result=str(path_result).replace('\\x00','').replace('\\x0','').replace('\\\\','\\')
                            result=result+path_result
                        for path_result2 in path_re2.findall(binary_encode):
                            path_result2=str(path_result2).replace('\\x00','').replace('\\x0','').replace('\\\\','\\')
                            result=result+path_result2

                        strings_ssdeep_hash.append(result)
                        
                    
                elif 'OLE' in stream[1].upper():
                    #ole 객체 내 스트링 파싱 -> 해석이 안되는 경우?
                    binary_encode_data=self.hwp_info.openstream('BinData/'+stream[1]).read()
                    binary_encode_data = zlib.decompress(binary_encode_data,-15)
                    binary_encode = str(binary_encode_data.hex())
                

                    
                    #MZ가 그대로 노출되었을 경우
                    if binary_encode_data.hex().find("4d5a90")!=-1:
                        print("MZ Detect")
                        binary_encode=str(binary_encode_data.hex())[str(binary_encode_data.hex()).find("4d5a90"):]
                        f = open(os.path.basename(self.FilePath)+stream[1],"wb")
                        f.write(bytearray.fromhex(binary_encode))
                        f.close()
                        file_ssdeep_hash=ssdeep.hash_from_file(os.path.basename(self.FilePath)+stream[1])
                        file_ssdeep_hash_list.append(file_ssdeep_hash)
                    ##MZ가 스트링 형태로 그대로 존재할 시##
                    elif binary_encode_data.hex().find("346435613930")!=-1:
                        print("MZ Detect")
                        detect_point=str(binary_encode_data.hex()).find("346435613930")
                        binary_encode=str(binary_encode_data.hex())[detect_point:]
                        binary_encode=binascii.unhexlify(str(binary_encode))
                        binary_encode=binascii.unhexlify(str(binary_encode.decode()))
                        f = open(os.path.basename(self.FilePath)+stream[1],"wb")
                        f.write(binary_encode)
                        f.close()
                        file_ssdeep_hash=ssdeep.hash_from_file(os.path.basename(self.FilePath)+stream[1])
                        file_ssdeep_hash_list.append(file_ssdeep_hash)
                    
                    
                    else:
                        #쉘코드 파싱은 불가능하고, 문자열만 추출해야될 경우 
                        print("Extract Strings")
                        DEF_RE=re.compile('def(.*)def.*$')
                        DIM_RE=re.compile('DIM+\W[\w]+')
                        DIM_RE2=re.compile('DIM+\W[\w]+,\W[\w]+')
                        SET_RE=re.compile('SET\W\w+\W+=\W+\w+\([\W\w+]\w+\W\w+\W\)')
                        SET_RE2=re.compile( 'SET\W\w+\W+=\W+\w+\([\W\w+]\w+\W\w+\W\)')
                        private_re=re.compile('private[\W\w]+End [Subfunction]+')
                        path_re=re.compile('[a-z,A-Z]:[\\\w.\w]+')
                        path_re2=re.compile('[\\\\w]+[.\w]+')
                        ipaddress_re=re.compile('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
                        email_re=re.compile('^[a-zA-Z0-9+-_.]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
                        url_re=re.compile(r'^(?:(?:https|ftp|www)://)(?:\S+(?::\S*)?@)?(?:(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,})))(?::\d{2,5})?(?:/[^\s]*)?$')

                        try:
                            binary_encode=str(binary_encode_data.decode())
                        except:
                            try:
                                binary_encode=str(binary_encode_data.decode('utf-16'))
                            except:
                                binary_encode=str(binary_encode_data)
                        
                        result=''.join(DIM_RE.findall(binary_encode))
                        
                        result=result+''.join(DEF_RE.findall(binary_encode))
                        result=result+''.join(DIM_RE2.findall(binary_encode))
                        result=result+''.join(SET_RE.findall(binary_encode))
                        result=result+''.join(SET_RE2.findall(binary_encode))
                        result=result+''.join(private_re.findall(binary_encode))
                        result=result+''.join(ipaddress_re.findall(binary_encode))
                        result=result+''.join(url_re.findall(binary_encode))
                        result=result+''.join(email_re.findall(binary_encode))
                        
                        for path_result in path_re.findall(binary_encode):
                            path_result=str(path_result).replace('\\x00','').replace('\\x0','').replace('\\\\','\\')
                            result=result+path_result
                        for path_result2 in path_re2.findall(binary_encode):
                            path_result2=str(path_result2).replace('\\x00','').replace('\\x0','').replace('\\\\','\\')
                            result=result+path_result2
                            
                        strings_ssdeep_hash.append(result)
       
        extract_ole_ps_ssdeep_dict={}
        if len(file_ssdeep_hash_list)==0:
            file_ssdeep_hash_list=None
            extract_ole_ps_ssdeep_dict['extract_file_ssdeep']=None
        else:
            extract_ole_ps_ssdeep_dict['extract_file_ssdeep']=file_ssdeep_hash_list    
        
        if len(strings_ssdeep_hash)==0:
            strings_ssdeep_hash=None
            extract_ole_ps_ssdeep_dict['extract_str_ssdeep']=strings_ssdeep_hash
        else:
            extract_ole_ps_ssdeep_dict['extract_str_ssdeep']=ssdeep.hash(' '.join(strings_ssdeep_hash))
        
        
        return extract_ole_ps_ssdeep_dict
                        
    def Detect_macro_script(self):
        distinction = True
        self.macro_parser_result_dic = {}
        
        script_data=self.hwp_info.openstream('Scripts/DefaultJScript').read()
        data = zlib.decompress(script_data,-15)
        for index,value in enumerate(data):
            if(eq(hex(value),'0x2f')):
                distinction = False
            if(distinction == True):
                if(eq(hex(value),'0x0')==False):
                    self.variable_source.append(chr(value))
            if(distinction==False):
                if(eq(hex(value),'0x0')==False):
                    self.macro_source.append(chr(value))
        
      
        variable_result = ''.join((self.variable_source[i]) for i in range(1,len(self.variable_source)-4))
        macro_result = ''.join((self.macro_source[i]) for i in range(1,len(self.macro_source)-4))
        
        variable_ssdeep=ssdeep.hash(variable_result)
        macro_ssdeep=ssdeep.hash(macro_result)
        
        # 다를 경우 
        if(len(macro_result) != 47 & macro_result.find('function OnDocument_New()')==-1):
            ip_match = re.compile(Regular_IP, re.MULTILINE)
            email_match = re.compile(Regular_email, re.MULTILINE)
            url_match = re.compile(Regular_url, re.MULTILINE)
        
            self.macro_parser_result_dic['ip'] = ip_match.findall("macro_result")
            self.macro_parser_result_dic['email'] = email_match.findall("macro_result")
            self.macro_parser_result_dic['url'] = url_match.findall("macro_result")
            self.macro_parser_result_dic['variable_ssdeep']=ssdeep.hash(variable_result)
            self.macro_parser_result_dic['macro_ssdeep']=ssdeep.hash(macro_result)
        
        # 기존과 같은 경우 
        else:
            self.macro_parser_result_dic['variable_ssdeep']='None'
            self.macro_parser_result_dic['macro_ssdeep']='None'
            self.macro_parser_result_dic['ip'] = 'None'
            self.macro_parser_result_dic['email'] = 'None'
            self.macro_parser_result_dic['url'] = 'None'

        
        return self.macro_parser_result_dic
        
'''

#Table : Header-parser
 Header_parser_result_dic
    ###insert
    q_master = ElasticQueryMaster.ElasticQueryMaster()
    document = {
        'sha256': file_sha256_hash, 
        'group': groups,
        'file_name':file_name,
        'Title': Title,
        'Subject':Subject,
        'Author':Author,
        'Comments':Comments,
        'Last_Saved_By':Last_Saved_By,
        'Revision_Number':Revision_Number,
        'Creat_Time_Data':Creat_Time_Data,
        'Last_saved_Time_Data':Last_saved_Time_Data,
        'Last_Printed':Last_Printed,
        'ip':ip,
        'email':email,
        'url':url
        
    }
    q_master.insert(document=document, index="Header-parser", doc_type="record")
    
    ###compare
    #create query
    should_query=[]
    if Author!="None" or Author!=None:
        should_query.append({ "match": { "Author" :Author}})
    if Comments!="None"or Comments!=None:
        should_query.append({ "match": { "Comments" :Comments}})
    if Revision_Number!="None"or Revision_Number!=None:
        should_query.append({ "match": { "Revision_Number" :Revision_Number}})
    if Keywords!="None" or Keywords!=None:
        should_query.append({ "match": { "Keywords" :Keywords}})
    if Subject!="None" or Subject!=None:
        should_query.append({ "match": { "Subject" :Subject}})
    if Last_Saved_By!="None" or Last_Saved_By!=None:
        should_query.append({ "match": { "Last_Saved_By" :Last_Saved_By}})
    ela = ElasticQueryMaster.ElasticQueryMaster()
    query = {  
        "query":{
            "bool": {
              "should": should_query
            }
        }
    }
    hwpinfo_search_result_list = ela.search(index="Header-parser", query=query, query_cut_level=1)

#Table : macro-parser
 macro_parser_result_dic
    ###insert
    q_master = ElasticQueryMaster.ElasticQueryMaster()
    document = {
        'sha256': file_sha256_hash, 
        'group': groups,
        'file_name':file_name,
        'variable_ssdeep': variable_ssdeep,
        'macro_ssdeep':macro_ssdeep
    }
    q_master.insert(document=document, index="macro-parser", doc_type="record")
    
    
    ###compare
    #create query
    matching_items = Elastic.get_matching_items_by_ssdeep(variable_ssdeep, 50)
    matching_items = Elastic.get_matching_items_by_ssdeep(macro_ssdeep, 50)

    
#Table : extract-parser
 extract_ole_ps_ssdeep_dict

    ###insert
    q_master = ElasticQueryMaster.ElasticQueryMaster()
    document = {
        'sha256': file_sha256_hash, 
        'group': groups,
        'file_name':file_name,
        'extract_str_ssdeep': extract_str_ssdeep,
        'extract_file_ssdeep':extract_file_ssdeep
    }
    q_master.insert(document=document, index="extract-parser", doc_type="record")
    
    
    ###compare
    #create query
    extract_file_ssdeep = Elastic.get_matching_items_by_ssdeep(extract_file_ssdeep, 50)
    extract_str_ssdeep = Elastic.get_matching_items_by_ssdeep(extract_str_ssdeep, 50)
    
################   Table 이름 : hwp-infos   ########################
{
'Last_Saved_By': 'MalDaeGaRi\x00',
 'Author': 'Administrator\x00',
 'extract_str_ssdeep': [' 500{/A1 65535 string dup 0 D40 putinterval def A1}repeat}def A/D41 5 dict def D41 begin/K_1 1000 array def/K_2 10000 array def/K_3 1000 array def/K_4 1000 array def/K_5 1000 array def/K_6 1000 array def/K_7 1000 array def/K_8 1000 array def D41 end/D42 3 dict def D42 begin/K_1 1000 array def D42 end /D43 0 def D41{D43 1 eq{/D44 exch def/D45 exch def exit} if pop pop  44 string pop 44 string pop 44 string pop 44 string pop 44 string pop 44 string pop 44 string pop 44 string pop 44 string pop 44 string pop 44 string pop 44 string pop 44 string pop 44 string pop 44 string pop 44 string pop 3 3 3 3 3 3 D42 D41 copy pop array pop array pop array pop array pop array pop array 1 1280 put 35 string pop 35 string pop 35 string 0<00000000ff030000030000000000000000000000464846480005000000000000000000>putinterval/D43 D43 1 add def} forall/D46 exch def/D47 exch def dup<0000000000C2C41008000000022222>search{length/D48 exch def pop pop}/D46 exch def/D47 exch def dup<0000000000C2C41008000000011111>search{length/D48 exch def pop pop}/B{pop 193883243 B 0}bind def/B{pop 399732316 B 0}bind def/B{pop 199383283 B 0}bind def/B{pop 58323832 B 0}bind def/B{pop 38829384 B 0}bind def revision 871 eq{/D41 5 dict def D41 begin/K_1 1000 array def/K_2 10000 array def/K_3 1000 array def/K_4 1000 array def/K_5 1000 array def/K_6 1000 array def/K_8 1000 array def D41 end D41}if/B{pop 485499355 B 0}bind def/B{pop 193874382 B 0}bind def/B{pop 487859398 B 0} bind def/B{pop 3883823 B 0}bind def/B{pop 0 B 0}bind def/B{pop 1024 B 0}bind def/B{pop 4 B 0} bind def/B{pop 48329384 B 0}bind def/B{pop 38234322 B 0}bind '],
 'url': 'None',
 'email': 'None',
 'Keywords': '\x00',
 'extract_file_ssdeep': None,
 'variable_ssdeep': 'None',
 'Creat_Time_Data': '2009-03-18 02:18:10.765000',
 'Comments': '\x00',
 'Last_Printed': '1601-01-01 00:00:00.000000',
 'ip': 'None',
 'Revision_Number': '9,0,0,562 WIN32LEWindows_Unknown_Version\x00',
 'macro_ssdeep': 'None',
 'Title': '우려되는 북한\x00',
 'Subject': '\x00',
 'Last_saved_Time_Data': '2016-11-03 02:13:07.593000'
 }
 
 
 {
    "properties" : {
      "chunksize" : {
        "type" : "integer"
      },
      "file_name" : {
        "type" : "keyword"
      },
      "group" : {
        "type" : "keyword"
      },
      "macro_chunk" : {
        "type" : "text",
        "analyzer" : "ssdeep_analyzer"
      },
      "macro_double_chunk" : {
        "type" : "text",
        "analyzer" : "ssdeep_analyzer"
      },
      "macro_ssdeep" : {
        "type" : "keyword"
      },
      "sha256" : {
        "type" : "keyword"
      },
      "variable_chunk" : {
        "type" : "text",
        "analyzer" : "ssdeep_analyzer"
      },
      "variable_double_chunk" : {
        "type" : "text",
        "analyzer" : "ssdeep_analyzer"
      },
      "variable_ssdeep" : {
        "type" : "keyword"
      }
    }
  }
  
  
  extract-parser
{
        "properties" : {
          "chunksize" : {
            "type" : "integer"
          },
          "extract_file_chunk" : {
            "type" : "text",
            "analyzer" : "ssdeep_analyzer"
          },
          "extract_file_double_chunk" : {
            "type" : "text",
            "analyzer" : "ssdeep_analyzer"
          },
          "extract_file_ssdeep" : {
            "type" : "keyword"
          },
          "extract_str_chunk" : {
            "type" : "text",
            "analyzer" : "ssdeep_analyzer"
          },
          "extract_str_double_chunk" : {
            "type" : "text",
            "analyzer" : "ssdeep_analyzer"
          },
          "extract_str_ssdeep" : {
            "type" : "keyword"
          },
          "file_name" : {
            "type" : "keyword"
          },
          "group" : {
            "type" : "keyword"
          },
          "sha256" : {
            "type" : "keyword"
          }
        }
      }
    
'''
def hwp_get_matching_items_by_ssdeep(ssdeep_value, threshold_grade,table_names,colum):
    """
    A function that finds matching items by ssdeep comparison with optimizations using ElasticSearch
    :param ssdeep_value: The ssdeep hash value of the item
    :param threshold_grade: The grade being used as a threshold, only items that pass this grade will be returned
    :return: A List of matching items (in this case, a list of sha256 hash values)
    """
    chunksize, chunk, double_chunk = ssdeep_value.split(':')
    chunksize = int(chunksize)

    es = elasticsearch.Elasticsearch(['localhost:9200'])

    query = {
        'query': {
            'bool': {
                'must': [
                    {
                        'terms': {
                            colum+'_chunksize': [chunksize, chunksize * 2, int(chunksize / 2)]
                        }
                    },
                    {
                        'bool': {
                            'should': [
                                {
                                    'match': {
                                        colum+'_chunk': {
                                            'query': chunk
                                        }
                                    }
                                },
                                {
                                    'match': {
                                        colum+'_double_chunk': {
                                            'query': double_chunk
                                        }
                                    }
                                }
                            ],
                            'minimum_should_match': 0
                        }
                    }
                ]
            }
        }
    }
    

    results = es.search(table_names, body=query)

class hwp_compare:
    def __init__(self,result_dict):
        self.result_dict=result_dict
        self.group_list_path=os.listdir('/home/bob/Malware_Sample')
        
    def Header_compare(self):
        Header_compare_Groups_Count={}
        for group in self.group_list_path:
            Header_compare_Groups_Count[group]=0
        
        
        Last_Saved_By=self.result_dict['Last_Saved_By']
        Author=self.result_dict['Author']
        Keywords=self.result_dict['Keywords']
        Comments=self.result_dict['Comments']
        Revision_Number=self.result_dict['Revision_Number']
        Title=self.result_dict['Title']
        Last_saved_Time_Data=self.result_dict['Last_saved_Time_Data']
        Subject=self.result_dict['Subject']
        ip=self.result_dict['ip']
        url=self.result_dict['url']
        email=self.result_dict['email']
        
        
        #create query
        should_query=[]
        if Author!="None" or Author!=None:
            should_query.append({ "match": { "Author" :Author}})
        if Comments!="None"or Comments!=None:
            should_query.append({ "match": { "Comments" :Comments}})
        if Revision_Number!="None"or Revision_Number!=None:
            should_query.append({ "match": { "Revision_Number" :Revision_Number}})
        if Keywords!="None" or Keywords!=None:
            should_query.append({ "match": { "Keywords" :Keywords}})
        if Subject!="None" or Subject!=None:
            should_query.append({ "match": { "Subject" :Subject}})
        if Last_Saved_By!="None" or Last_Saved_By!=None:
            should_query.append({ "match": { "Last_Saved_By" :Last_Saved_By}})
        if ip!="None" or ip!=None:
            should_query.append({ "match": { "ip" :ip}})
        if url!="None" or url !=None:
            should_query.append({ "match": { "url" :url}})
        if email!=None or email!=None:
            should_query.append({ "match": { "email" :email}}) 

        ###########################################elastic search###########################
        ela = ElasticQueryMaster.ElasticQueryMaster()
        query = {  
            "query":{
                "bool": {
                  "should": should_query
                }
            }
        }
        hwpinfo_search_result_list = ela.search(index="Header-parser", query=query, query_cut_level=1)
        ####################################################################################
        if len(hwpinfo_search_result_list)>0:
            for hwpinfo_search_result_object in hwpinfo_search_result_list:
                if 'Magniber'==hwpinfo_search_result_object['_source']['group']:
                    Groups_Names="Megniber"
                elif 'GlobeImposter'==hwpinfo_search_result_object['_source']['group']:
                    Groups_Names="Globelmposter"
                elif 'XOR_TRANSFORM' in hwpinfo_search_result_object['_source']['group']:
                    Groups_Names="Andariel"
                elif 'akdoor' in hwpinfo_search_result_object['_source']['group']:
                    Groups_Names="Lazarus"
                else:
                    Groups_Names=hwpinfo_search_result_object['_source']['group']
                
                
                if pdb_name!="None":
                    if email==hwpinfo_search_result_object['_source']["email"]:
                        Header_compare_Groups_Count[Groups_Names]=op.add(Header_compare_Groups_Count[Groups_Names],1)
                if url!="None":
                    if url==hwpinfo_search_result_object['_source']["url"]:
                        Header_compare_Groups_Count[Groups_Names]=op.add(Header_compare_Groups_Count[Groups_Names],1)
                if ip!="None":
                    if ip==hwpinfo_search_result_object['_source']["ip"]:
                        Header_compare_Groups_Count[Groups_Names]=op.add(Header_compare_Groups_Count[Groups_Names],1)
                if Last_Saved_By!="None":
                    if Last_Saved_By==hwpinfo_search_result_object['_source']["Last_Saved_By"]:
                        Header_compare_Groups_Count[Groups_Names]=op.add(Header_compare_Groups_Count[Groups_Names],1)
                if Subject!="None":
                    if Subject==hwpinfo_search_result_object['_source']["Subject"]:
                        Header_compare_Groups_Count[Groups_Names]=op.add(Header_compare_Groups_Count[Groups_Names],1)
                if Keywords!="None":
                    if Keywords==hwpinfo_search_result_object['_source']["Keywords"]:
                        Header_compare_Groups_Count[Groups_Names]=op.add(Header_compare_Groups_Count[Groups_Names],1)
                if Revision_Number!="None":
                    if Revision_Number==hwpinfo_search_result_object['_source']["Revision_Number"]:
                        Header_compare_Groups_Count[Groups_Names]=op.add(Header_compare_Groups_Count[Groups_Names],1)
                if Author!="None":
                    if Author==hwpinfo_search_result_object['_source']["Author"]:
                        Header_compare_Groups_Count[Groups_Names]=op.add(Header_compare_Groups_Count[Groups_Names],1)
                        
        Header_compare_Groups_total=list(Header_compare_Groups_Count.values())
        Header_compare_Groups_total=sum(Header_compare_Groups_total)
        return  Header_compare_Groups_Count, Header_compare_Groups_total
    
    def Macro_compare(self):
        Macro_compare_Groups_Count={}
        for group in self.group_list_path:
            Macro_compare_Groups_Count[group]=0
        
        
        variable_ssdeep=self.result_dict['variable_ssdeep']
        macro_ssdeep=self.result_dict['macro_ssdeep']
        ###colum
        #macro
        #variable
        #extract_str
        #extract_file
        variable_ssdeep_matching_items = hwp_get_matching_items_by_ssdeep(variable_ssdeep, 50,'macro-parser','variable')
        macro_ssdeep_matching_items = hwp_get_matching_items_by_ssdeep(macro_ssdeep, 50,'macro-parser','macro')
        result=variable_ssdeep_matching_items+macro_ssdeep_matching_items
        
        if len(result)>=1:
            for items in result:
                if 'Magniber'==items['group']:
                    Groups_Names="Megniber"
                elif 'GlobeImposter'==items['group']:
                    Groups_Names="Globelmposter"
                elif 'XOR_TRANSFORM_WILDCARD'==items['group']:
                    Groups_Names="Andariel"
                elif 'akdoor' in items['group']:
                    Groups_Names="Lazarus"
                else:
                    Groups_Names=items['group']

                Macro_compare_Groups_Count[Groups_Names]=op.add(Macro_compare_Groups_Count[Groups_Names],1)
            
        Macro_compare_Groups_total=list(Macro_compare_Groups_Count.values())
        Macro_compare_Groups_total=sum(Macro_compare_Groups_total)
        return  Macro_compare_Groups_Count, Macro_compare_Groups_total
        
    def Extract_ole_ps_compare(self):
        Extract_ole_ps_Groups_Count={}
        for group in self.group_list_path:
            Extract_ole_ps_Groups_Count[group]=0
        
        extract_str_ssdeep=ssdeep.hash(' '.join(self.result_dict['extract_str_ssdeep']))
        extract_file_ssdeep=self.result_dict['extract_file_ssdeep']
        extract_file_ssdeep_matching_items = hwp_get_matching_items_by_ssdeep(extract_file_ssdeep, 50,'extract-parser','extract_file')
        extract_str_ssdeep_matching_items = hwp_get_matching_items_by_ssdeep(extract_str_ssdeep, 50,'extract-parser','extract_str')
        result=extract_file_ssdeep_matching_items+extract_str_ssdeep_matching_items
        
        if len(result)>=1:
            for items in result:
                if 'Magniber'==items['group']:
                    Groups_Names="Megniber"
                elif 'GlobeImposter'==items['group']:
                    Groups_Names="Globelmposter"
                elif 'XOR_TRANSFORM_WILDCARD'==items['group']:
                    Groups_Names="Andariel"
                elif 'akdoor' in items['group']:
                    Groups_Names="Lazarus"
                else:
                    Groups_Names=items['group']

                Extract_ole_ps_Groups_Count[Groups_Names]=op.add(Extract_ole_ps_Groups_Count[Groups_Names],1)
            
        Extract_ole_ps_Groups_total=list(Extract_ole_ps_Groups_Count.values())
        Extract_ole_ps_Groups_total=sum(Extract_ole_ps_Groups_total)
        return  Extract_ole_ps_Groups_Count, Extract_ole_ps_Groups_total
        
        
    def sims_rates(self,group_count,group_total):
        sims_rates_Groups_Count={}
        for group in self.group_list_path:
            sims_rates_Groups_Count[group]=0
            
            
        try:
            for group_names in group_count:
                sims_rates_Groups_Count[group_names]=int('{:.0%}'.format(group_count[group_names]/group_total).replace('%',''))
                if sims_rates_Groups_Count[group_names]==0:
                    continue
        except ZeroDivisionError:
            pass
        return sims_rates_Groups_Count

    def weight_process(result_lists):
        weight_process_Groups_Count={}
        for group in self.group_list_path:
            weight_process_Groups_Count[group]=0
            
        Header_compare_result=result_lists['Header_compare_result']
        for group_names in Header_compare_result:
            if Header_compare_result[group_names]==0:
                continue
            weight_process_Groups_Count[group_names]=int(weight_process_Groups_Count[group_names]+(Header_compare_result[group_names]*30/100))

        Macro_compare_result=result_lists['Macro_compare_result']
        for group_names in Macro_compare_result:
            if Macro_compare_result[group_names]==0:
                continue
            weight_process_Groups_Count[group_names]=int(weight_process_Groups_Count[group_names]+(Macro_compare_result[group_names]*35/100))
            
        Extract_ole_ps_compare_result=result_lists['Extract_ole_ps_result']
        for group_names in Extract_ole_ps_compare_result:
            if Extract_ole_ps_compare_result[group_names]==0:
                continue
            weight_process_Groups_Count[group_names]=int(weight_process_Groups_Count[group_names]+(Extract_ole_ps_compare_result[group_names]*35/100))

        return weight_process_Groups_Count

    def weight_total_score(self,Header_compare_Groups_Count, Header_compare_Groups_total,
                                Macro_compare_Groups_Count, Macro_compare_Groups_total, 
                                Extract_ole_ps_Groups_Count, Extract_ole_ps_Groups_total):
        weight_total_Groups_Count={}
        for group in self.group_list_path:
            weight_total_Groups_Count[group]=0


        Header_compare_result=self.sims_rates(Header_compare_Groups_Count,Header_compare_Groups_total)
        Macro_compare_result=self.sims_rates(Macro_compare_Groups_Count,Macro_compare_Groups_total)
        Extract_ole_ps_result=self.sims_rates(Extract_ole_ps_Groups_Count,Extract_ole_ps_Groups_total)
        
        result_lists={
            'Header_compare_result':Header_compare_result,
            'Macro_compare_result':Macro_compare_result,
            'Extract_ole_ps_result':Extract_ole_ps_result
        }
        weight_Total_Score_Groups=self.weight_process(result_lists)
        
        return result_lists,weight_Total_Score_Groups
        
        
        
        
        
###########################################################################################        
        

class hwp_insert:
    def __init__(self,result_dict,file_path,groups=None):
        self.q_master = ElasticQueryMaster.ElasticQueryMaster()
        
        self.result_dict=result_dict
        self.file_path=file_path
        self.sha256=getHash(self.file_path)
        self.groups=groups
        
        
        
    def insert_header_data(self):
        document = {
            "sha256" : self.sha256,
            "file_name" : os.path.basename(self.file_path),
            "group" : self.groups,
            
            "Title": str(self.result_dict['Title']).replace('\x00',''),
            "Subject" : str(self.result_dict['Subject']).replace('\x00',''),
            "Author" : str(self.result_dict['Author']).replace('\x00',''),
            "keywords": str(self.result_dict['Keywords']).replace('\x00',''),
            "Comments": str(self.result_dict['Comments']).replace('\x00',''),
            "Last_Saved_By": str(self.result_dict['Last_Saved_By']).replace('\x00',''),
            "Revision_Number": str(self.result_dict['Revision_Number']).replace('\x00',''),
            "Create_Time/Data": str(self.result_dict['Create_Time_Data']).replace('\x00',''),
            "Last_Saved_Time/Data": str(self.result_dict['Last_saved_Time_Data']).replace('\x00',''),
            "Last_Printed" : str(self.result_dict['Last_Printed']).replace('\x00',''),
            "ip": str(self.result_dict['ip']).replace('\x00',''),   
            "email": str(self.result_dict['email']).replace('\x00',''),
            "url" : str(self.result_dict['url']).replace('\x00','')
        }
        self.q_master.insert(document=document, index="header-parser", doc_type="record")
        
    def insert_macro_data(self):
        variable_ssdeep=self.result_dict['variable_ssdeep']
        macro_ssdeep=self.result_dict['macro_ssdeep']
        
        variable_chunksize=None
        variable_chunk=None
        variable_double_chunk=None
        macro_chunksize=None
        macro_chunk=None
        macro_double_chunk=None
        
        
        
        if variable_ssdeep!="None":
            variable_chunksize, variable_chunk, variable_double_chunk = self.result_dict['variable_ssdeep'].split(':')
            variable_chunksize = int(variable_chunksize)
        if macro_ssdeep!="None":
            macro_chunksize, macro_chunk, macro_double_chunk = self.result_dict['macro_ssdeep'].split(':')
            macro_chunksize = int(macro_chunksize)
        elif variable_ssdeep=="None" and macro_ssdeep=="None":
            return
        
        document = {
    
              "macro_chunksize":macro_chunksize,
              "variable_chunksize":variable_chunksize,
              "file_name" : os.path.basename(self.file_path),
              "group" : self.groups,
              "macro_chunk" : macro_chunk,
              "macro_double_chunk" : macro_double_chunk,
              "macro_ssdeep" : self.result_dict['macro_ssdeep'],
              "sha256" : self.sha256,
              "variable_chunk" : variable_chunk,
              "variable_double_chunk" : variable_double_chunk,
              "variable_ssdeep" :self.result_dict['variable_ssdeep'] 
        }
        
        self.q_master.insert(document=document, index="macro-parser", doc_type="record")
  
    
    def insert_extract_data(self):    
        extract_str_ssdeep=self.result_dict['extract_str_ssdeep']
        extract_file_ssdeep=self.result_dict['extract_file_ssdeep']
        
        extract_str_chunksize=None
        extract_str_chunk=None
        extract_str_double_chunk=None
        extract_file_chunksize=None
        extract_file_chunk=None
        extract_file_double_chunk=None
        
        
        if extract_str_ssdeep!=None:
            extract_str_chunksize, extract_str_chunk, extract_str_double_chunk = extract_str_ssdeep.split(':')
            extract_str_chunksize = int(extract_str_chunksize)
        
        if extract_file_ssdeep!=None:
            if len(extract_file_ssdeep)>1:
                for extract_file in extract_file_ssdeep:
                    extract_file_chunksize, extract_file_chunk, extract_file_double_chunk = extract_file.split(':')
                    extract_file_chunksize = int(extract_file_chunksize)
        
    
                    document = {
                          "extract_str_chunksize" : extract_str_chunksize,
                          "extract_file_chunksize" : extract_file_chunksize,
                          "extract_file_chunk" : extract_file_chunk,
                          "extract_file_double_chunk" : extract_file_double_chunk,
                          "extract_file_ssdeep" : extract_file,
                          "extract_str_chunk" : extract_str_chunk,
                          "extract_str_double_chunk" : extract_str_double_chunk,
                          "extract_str_ssdeep" :self.result_dict['extract_str_ssdeep'],
                          "file_name" : os.path.basename(self.file_path),
                          "group" : self.groups,
                          "sha256" : self.sha256
                     }
                    self.q_master.insert(document=document, index="extract-parser", doc_type="record")
                        
            elif len(extract_file_ssdeep)==1:
                extract_file_chunksize, extract_file_chunk, extract_file_double_chunk = extract_file_ssdeep[0].split(':')
                extract_file_chunksize = int(extract_file_chunksize)
                document = {
                      "extract_str_chunksize" : extract_str_chunksize,
                      "extract_file_chunksize" : extract_file_chunksize,
                      "extract_file_chunk" : extract_file_chunk,
                      "extract_file_double_chunk" : extract_file_double_chunk,
                      "extract_file_ssdeep" : extract_file_ssdeep[0],
                      "extract_str_chunk" : extract_str_chunk,
                      "extract_str_double_chunk" : extract_str_double_chunk,
                      "extract_str_ssdeep" :self.result_dict['extract_str_ssdeep'],
                      "file_name" : os.path.basename(self.file_path),
                      "group" : self.groups,
                      "sha256" : self.sha256
                 }
                self.q_master.insert(document=document, index="extract-parser", doc_type="record")



        if extract_file_ssdeep==None and extract_str_ssdeep==None:
            return


        document = {
              "extract_str_chunksize" : extract_str_chunksize,
              "extract_file_chunksize" : extract_file_chunksize,
              "extract_file_chunk" : extract_file_chunk,
              "extract_file_double_chunk" : extract_file_double_chunk,
              "extract_file_ssdeep" : extract_file_ssdeep,
              "extract_str_chunk" : extract_str_chunk,
              "extract_str_double_chunk" : extract_str_double_chunk,
              "extract_str_ssdeep" :self.result_dict['extract_str_ssdeep'],
              "file_name" : os.path.basename(self.file_path),
              "group" : self.groups,
              "sha256" : self.sha256
         }
        self.q_master.insert(document=document, index="extract-parser", doc_type="record")



def result_parsing(Header_Parser_result_dic,macro_parser_result_dic,extract_ole_ps_ssdeep_dict,file_path):
    
    Header_Parser_result_dic['ip'] = macro_parser_result_dic['ip']
    Header_Parser_result_dic['email'] = macro_parser_result_dic['email']
    Header_Parser_result_dic['url'] = macro_parser_result_dic['url']
    
    result_dic = {}
    result_dic.update(Header_Parser_result_dic)
    result_dic.update(macro_parser_result_dic)
    result_dic.update(extract_ole_ps_ssdeep_dict)
    result_dic['sha256']=getHash(file_path)
    #print(result_dic)
    return result_dic
    '''
    ###결과물 json 덤프###
    dt = datetime.now()
    json_file_name='{}{}{}{}{}{}'.format(dt.year,dt.month,dt.day,dt.hour,dt.minute,dt.microsecond)
    json_file_full_path=os.path.join(os.getcwd(),json_file_name)+'.json'
    with open(json_file_full_path, 'w', encoding="utf-8") as make_file:
        json.dump(result_dic, make_file, ensure_ascii=False, indent="\t")

    ###json 파일 읽음##
    json_file_read=open(json_file_full_path,encoding='utf-8').read()
    json_data=json.loads(json_file_read)

    print(json_data)
    '''
    
def main_inserts():
    sample_path='/home/bob/HWP_Malware_sample'
    
    for dirpath, dirname, filenames in os.walk('/home/bob/HWP_Malware_sample'):
        break
    
    for groups in dirname:
        for group_samples in os.listdir(os.path.join(sample_path,groups)):
            sample_full_path=os.path.join(sample_path,groups,group_samples)
            HWP_HeaderParser_class = hwp_parser(sample_full_path)
            Header_Parser_result_dic=HWP_HeaderParser_class.run()
        
            mal_obj=Malware_detect(sample_full_path)
            extract_ole_ps_ssdeep_dict=mal_obj.detect_PostScript()
            macro_parser_result_dic=mal_obj.Detect_macro_script()
        
            result_dict=result_parsing(Header_Parser_result_dic,macro_parser_result_dic,extract_ole_ps_ssdeep_dict,sample_full_path)
        
        
            insert_object=hwp_insert(result_dict,sample_full_path,groups)
            insert_object.insert_header_data()
            insert_object.insert_macro_data()
            insert_object.insert_extract_data()

if __name__ == '__main__': 
    main_inserts()
    
    #insert_object.insert_header_data(Header_Parser_result_dic)
    #insert_object.insert_header_data(macro_parser_result_dic)
    #insert_object.insert_header_data(extract_ole_ps_ssdeep_dict)
    
    
    
   # result_parsing(Header_Parser_result_dic,macro_parser_result_dic,extract_ole_ps_ssdeep_dict,file_path)

  
    #Malware_detect.Detect_macro_script()
    #print(Header_Parser_result_list)
    
    ##########################################
    
    
    #Detect_macro_script()
    #meta_data_parsing()
    # get_entry_test()
    