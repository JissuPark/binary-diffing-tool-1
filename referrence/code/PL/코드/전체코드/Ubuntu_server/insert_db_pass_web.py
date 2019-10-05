
#내부 모듈
import threading
from multiprocessing import Process, current_process,Queue, Pool
import hashlib
import sys, traceback
import logging
import os
import json
import glob
import re
import copy
import time
#외부 모듈
import idb
import pefile
import ssdeep
#만든 모듈
import File_Information as FI
import Elastic
import Integrated_idb
import ElasticQueryMaster

#로그
import logging
#logging.basicConfig(level=logging.DEBUG)

######################################################
mutex_file=open("mutex_strings_lists.txt",'r')
mutex_line=[]
while True:
    line = mutex_file.readline()
    if not line: break
    mutex_line.append(line.replace('\n',''))
mutex_file.close()
######################################################


class main_insert:
    def __init__(self,json_data):

        self.json_data=json_data
        self.file_ssdeep_hash=self.json_data['pe_ssdeephash']
        self.file_sha256_hash=self.json_data['pe_sha256']
        if type(self.json_data['pe_groups'])==list:
            self.json_data['pe_groups']=self.json_data['pe_groups'][0]
        
        if 'Megniber'==self.json_data['pe_groups']:
            self.groups="Magniber"
        elif 'GlobeImposter'==self.json_data['pe_groups']:
            self.groups="Globelmposter"
        else:
            self.groups=self.json_data['pe_groups']

        if 'Megniber'==self.json_data['pe_tags']:
            self.tags="Magniber"
        elif 'GlobeImposter'==self.json_data['pe_tags']:
            self.tags="Globelmposter"
        else:
            self.tags=self.json_data['pe_tags']


        self.file_name=self.json_data['pe_random']
        self.idb_sample_full_path='/home/bob/IDB_TMP/Idb_Sample'
        
        

        for self.idb_filename in os.listdir(self.idb_sample_full_path):
            if self.file_name.lower() in self.idb_filename:
                self.idb_filename=self.idb_filename
                break
            
                
        self.idb_filename_full_path=os.path.join(self.idb_sample_full_path,self.idb_filename)        


        
    #1. 파일 ssdeep 값 db에 저장
    def ssdeep_db_insert(self):
        ssdeep_result = Elastic.search_everything("malware_info", "sha256",self.file_sha256_hash.lower())
        if len(ssdeep_result)>1:
            return

        ssdeep_db_insert_data={
            'ssdeep_value':self.file_ssdeep_hash.lower(),
            'file_name':self.file_name.lower(),
            'group':self.groups,
            'last_updated' : time.time(),
            'sha256':self.file_sha256_hash,
            'tag':[self.groups,self.tags],
            'upload_date' : time.time()
        }
        Elastic.insert_record_to_ssdeep_index(ssdeep_db_insert_data)

        
        
    #2. basicblock 함수 대푯값, ssdeep 값 생성
    def basicblock_extract(self,basic_block_result_list):
        STR_CLASS=FI.STRINGS()
        MUTEX_LIST=[]
        FUNCTION_REPRE_LIST=[]
        BASIC_BLOCK_INDEX=0
        
        for function_block in basic_block_result_list:
            try:
                for basic_block in function_block:
                    basic_blocK_opcode_all=' '.join(basic_block.opcode)

                    opcode_hex_list=[]
                    for opcode_hex in basic_block.opcode:
                        opcode_hex_list.append(STR_CLASS.STR_HEX_COVERTER(opcode_hex))
                        
                    basic_block_opcode_hex_converte=STR_CLASS.STR_ADD(opcode_hex_list)
                    

                    #베이직 블록 내 opcode에 대한 xor 연산 후 해시 화 -> 함수 대푯값 선정
                    basic_block_repre_hash=hashlib.sha256(str(basic_block_opcode_hex_converte).encode()).hexdigest()
                    #HASH_OPCODE는 함수 대푯값을 의미함.

                    basic_block_ssdeep_hash=ssdeep.hash(basic_blocK_opcode_all,encoding='utf-8')
                    if basic_block_repre_hash in MUTEX_LIST:
                        continue

                    else:
                        FUNCTION_REPRE_LIST.append([basic_block_repre_hash,
                                                    basic_block_ssdeep_hash,
                                                    self.file_sha256_hash,
                                                    BASIC_BLOCK_INDEX,
                                                    basic_blocK_opcode_all,
                                                    basic_block.disasms])
                        
                        BASIC_BLOCK_INDEX=BASIC_BLOCK_INDEX+1
                        MUTEX_LIST.append(basic_block_repre_hash)
            except TypeError:
                print("typeerror")
                return None
            
            del(basic_blocK_opcode_all)
        del(MUTEX_LIST)
        return FUNCTION_REPRE_LIST

    #3 추출한 베이직 블록 DB에 삽입
    def DATABASE_INSERT(self,FUNCTION_REPRE_LIST):
        if FUNCTION_REPRE_LIST==None:
            return
        for BLOCK in FUNCTION_REPRE_LIST:
            if BLOCK==None:
                return
            self.FLAG_H=0
            self.FLAG_S=0
            self.HASH_OPCODE=BLOCK[0] #베이직 블록 함수 대푯 값
            self.SSDEEP_HASHS=BLOCK[1] #베이직 블록 SSDEEP 값
            self.FILE_HASH=BLOCK[2] #파일 해시
            self.BASIC_BLOCK_INDEX=BLOCK[3] #베이직 블록 인덱스
            self.BASIC_BLOCK_OPCODE_ALL=BLOCK[4] #베이직 블록 내 OPCODE 모든 값
            self.opcode_operand=BLOCK[5]
            # 그룹, 대푯값 둘다 일치하게 검색
            if type(self.groups)==list:
                self.groups=self.groups[0]
            Query_repre = {
                "query": {
                    "bool": {
                        "must": [
                            { "match": { "group" : self.groups }},
                            { "match": { "block_representative": self.HASH_OPCODE}}
                        ]
                    }    
                }
            }
            try:
                repre_query_result_list = Elastic._search_query("basic_block", Query_repre)
            except:
                print(Query_repre)
            #print(repre_query_result_list)
            #GROUP 검색 시 동일한 함수 대푯값이 있으면 SSDEEP 값이 같은지 유무를 판단한다.
            if len(repre_query_result_list)>0:
                #그룹과 repre 값이 일치한 것 중 ssdeep값이 일치한지 판단한다.
                
                for repre_query in repre_query_result_list:
                    Query_ssdeep = {
                        "query": {
                            "bool": {
                                "must": [
                                    { "match": { "group" : self.groups }},
                                    { "match": { "ssdeep": repre_query['ssdeep']}}
                                ]
                            }    
                        }
                    }
                    #그룹과 repre 값이 일치하는 것 중 ssdeep 값을 추출한다.
                    ssdeep_query_result_list = Elastic._search_query("basic_block", Query_ssdeep)
                    #print(ssdeep_query_result_list)
                    #추출한 ssdeep의 값이 샘플의 ssdeep과 유사한지 확인한다.
                    
                    #샘플의 ssdeep값과 데이터베이스에 있는 ssdeep 값이 일치할 시엔 FLAG_S를 1로 준 뒤 별도의 행위를 하지 않는다. (다음 repre 값으로 넘어간다.)
                    if len(ssdeep_query_result_list)>0:
                        for ssdeep_query_result in ssdeep_query_result_list:
                            if self.SSDEEP_HASHS==ssdeep_query_result['ssdeep']:
                                self.FLAG_S=1
                                break
                        
                        
                        if self.FLAG_S==1:
                            continue
                        
                        #그룹, repre 값은 일치하지만, ssdeep 값이 일치하는 게 없을 시
                        elif self.FLAG_S==0:
                            self.data={
                                'ssdeep_value':self.SSDEEP_HASHS, #베이직 블록 SSDEEP 값
                                'sha256':self.FILE_HASH,  #파일명이 해시임
                                'group':self.groups, #그룹 정보
                                'tag':[self.groups], #태그
                                'block_representative' : self.HASH_OPCODE, #베이직 블록 함수 대푯값
                                'block_count' : self.BASIC_BLOCK_INDEX, #베이직 블록 Index
                                'opcode' : self.BASIC_BLOCK_OPCODE_ALL, #베이직 블록 내 OPCODE
                                'disassemble' : self.opcode_operand
                            }
                            Elastic.insert_basic_block(self.data)
                            continue

                            
                    #그룹, repre값은 일치하지만, ssdeep값이 일치하는게 없을 시
                    else:
                        self.data={
                            'ssdeep_value':self.SSDEEP_HASHS, #베이직 블록 SSDEEP 값
                            'sha256':self.FILE_HASH,  #파일명이 해시임
                            'group':self.groups, #그룹 정보
                            'tag':[self.groups], #태그
                            'block_representative' : self.HASH_OPCODE, #베이직 블록 함수 대푯값
                            'block_count' : self.BASIC_BLOCK_INDEX, #베이직 블록 Index
                            'opcode' : self.BASIC_BLOCK_OPCODE_ALL, #베이직 블록 내 OPCODE
                            'disassemble' : self.opcode_operand
                        }
                        #print("DATA : {}\n".format(self.data))
                        Elastic.insert_basic_block(self.data)
                        continue
                    del(ssdeep_query_result_list)
            #Group 검색 시 동일함 함수 대푯값이 없으면 DB에 내용을 추가한다.
            else:
                self.data={
                    'ssdeep_value':self.SSDEEP_HASHS, #베이직 블록 SSDEEP 값
                    'sha256':self.FILE_HASH,  #파일명이 해시임
                    'group':self.groups, #그룹 정보
                    'tag':[self.groups], #태그
                    'block_representative' : self.HASH_OPCODE, #베이직 블록 함수 대푯값
                    'block_count' : self.BASIC_BLOCK_INDEX, #베이직 블록 Index
                    'opcode' : self.BASIC_BLOCK_OPCODE_ALL, #베이직 블록 내 OPCODE
                    'disassemble' : self.opcode_operand
                }
                Elastic.insert_basic_block(self.data)
                continue
            del(repre_query_result_list)

    #4단계 상숫값 데이터베이스 삽입
    def constant_value(self,constant_result_list):
        q_master = ElasticQueryMaster.ElasticQueryMaster()
        for constant_result_object in constant_result_list:
            constant_value=' '.join(constant_result_object)
            
            document = {
                'sha256': self.file_sha256_hash, 
                'group': self.groups,
                'file_name':self.file_name,
                'constant_value': constant_value
            }
            #print(document)
            q_master.insert(document=document, index="constant-value", doc_type="record")
            
    
    #4단계 rich_header
    def RH_insert(self):
        q_master = ElasticQueryMaster.ElasticQueryMaster()
        RichHeader=self.json_data['pe_richheader']
        if RichHeader==None:
            return None
            
        if RichHeader['xorkey']=="0x0":
            return None
        elif RichHeader['sample_clear_data']==[]:
            return None
        xorkey=RichHeader['xorkey']
        clear=RichHeader['sample_clear_data']
        count=RichHeader['count']
        prodid=RichHeader['prodid']
        build=RichHeader['build']

        
        document = {
            "file_name": self.file_name,
            "group": self.groups,
            "rich_header": "",
            "sha256": self.file_sha256_hash,
            "xor_key": xorkey,
            "clear_data": ' '.join(clear),
            "prod_id": prodid,
            "build": build,
            "count": count
        }
        try:
            q_master.insert(document=document, index="rich-header", doc_type="record")
        except:
            print(document)
            
    #5단계 callingdistance
    def Distance(self,distance_result_list):
        distance_result=distance_result_list
        if distance_result=="nan" or distance_result==None:
            return None

        #정수형으로 변환
        try:
            distance_result=int(distance_result)
        except:
            pass

        q_master = ElasticQueryMaster.ElasticQueryMaster()
        document = {
            "file_name": self.file_name,
            "group": self.groups,
            "distance": distance_result,
            "sha256": self.file_sha256_hash,
        }
        try:
            q_master.insert(document=document, index="calling-distance", doc_type="record")
        except:
            print(document)
    
    #6단계 PeInfo   PDB,imphash,codesign
    def peinfo(self):
        #pdb
        pdb_dic_data=self.json_data['pe_pdb']
        pdb_dic_data['Name']
        pdb_dic_data['Age']
        #imphash
        imp_hash_data=self.json_data['pe_imphash']
        #codesign
        code_sign_data=self.json_data['pe_codesign']
        
        q_master = ElasticQueryMaster.ElasticQueryMaster()
        document = {
            "file_name": self.file_name,
            "group": self.groups,
            "sha256": self.file_sha256_hash,
            ##pdb##
            "age":pdb_dic_data['Age'],
            "pdb_name":pdb_dic_data['Name'],
            #경로에 대해선 추후 Ngram Search
            "pdb_path":' '.join(pdb_dic_data['Pdbpath'].split('\\')[5:]),
            #GUID는 T/F 매칭
            "pdb_guid":pdb_dic_data['GUID'],
            ##imphash##
            "imphash":imp_hash_data,
            ##codesign##
            "codesign":code_sign_data
        }
        try:
            q_master.insert(document=document, index="peinfos", doc_type="record")
        except:
            print(document)
            
            
            
    #7단계 strings insert db
    def strings_insert(self):
        #strings
        strings_lists=self.json_data['pe_strings']
        

        ipaddress_re=re.compile('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
        email_re=re.compile('^[a-zA-Z0-9+-_.]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
        url_re=re.compile(r'^(?:(?:https|ftp|www)://)(?:\S+(?::\S*)?@)?(?:(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,})))(?::\d{2,5})?(?:/[^\s]*)?$')

        mutex1=re.compile("[@]")
        mutex2=re.compile("[?]")
        mutex3=re.compile("[=]")
        mutex4=re.compile("[\w]")
        mutex5=re.compile("[\W]")
        
        
        sample_str_list=[]
        
        for index,sample_str in enumerate(strings_lists):
            if sample_str in mutex_line:
                continue
            
            #important strings
            if len(ipaddress_re.findall(sample_str))>=1:
                sample_str_list.append(sample_str)
                continue
            elif len(email_re.findall(sample_str))>=1:
                sample_str_list.append(sample_str)
                continue
            elif len(url_re.findall(sample_str))>=1:
                sample_str_list.append(sample_str)
                continue
            elif 'exe' in sample_str or 'dll' in sample_str:
                sample_str_list.append(sample_str)
                continue
            elif 'www' in sample_str or 'http' in sample_str:
                sample_str_list.append(sample_str)
                continue
            elif 'POST' in sample_str.upper() or 'GET' in sample_str.upper():
                sample_str_list.append(sample_str)
                continue
            
            
            #mutext strings
            if 'PAD' in sample_str:
                continue
            elif '__' in sample_str:
                continue
            elif '$' in sample_str:
                continue
            elif len(mutex1.findall(sample_str))>1:
                continue
            elif len(mutex2.findall(sample_str))>2:
                continue
            elif len(mutex3.findall(sample_str))>2:
                continue
            elif len(set(mutex4.findall(sample_str)))<=7:
                continue
            elif len(set(mutex5.findall(sample_str)))>2:
                continue
            else:
                sample_str_list.append(sample_str)
    
            if index % 15 == 0:
                sample_strings=' '.join(sample_str_list)
                if len(sample_strings)<3:
                    continue
                q_master = ElasticQueryMaster.ElasticQueryMaster()
                document = {
                    "file_name": self.file_name,
                    "group": self.groups,
                    "sha256": self.file_sha256_hash,
                    "strings":sample_strings
                }
                try:
                    q_master.insert(document=document, index="pe_strings", doc_type="record")
                except:
                    print(document)
                sample_str_list=[]
                
    
        sample_strings=' '.join(sample_str_list)
        if len(sample_strings)<3:
            return
        q_master = ElasticQueryMaster.ElasticQueryMaster()
        document = {
            "file_name": self.file_name,
            "group": self.groups,
            "sha256": self.file_sha256_hash,
            "strings":sample_strings
        }
        try:
            q_master.insert(document=document, index="pe_strings", doc_type="record")
        except:
            print(document)


            
        
#main
#json 파일을 
class main_db_insert_cla:
    def __init__(self,queue):
        self.json_folder_full_path='/home/bob/IDB_TMP/json'
        self.idb_sample_full_path='/home/bob/IDB_TMP/Idb_Sample'
        self.queue=queue
    
    def queue_put(self):
        
        for json_file in os.listdir(self.json_folder_full_path):
            self.queue.put(os.path.join(self.json_folder_full_path,json_file))

    def idb_creator(self,idb_sample_full_path):
        try:
            with idb.from_file(idb_sample_full_path) as db:
                api=idb.IDAPython(db)
                basic_block_result_list, constant_result_list, distance_result_list = Integrated_idb.main(api,idb_sample_full_path)
                return basic_block_result_list, constant_result_list, distance_result_list
        except:
            return None
        
    def main_db_insert_function(self,queue):
        os.system("chmod -R 4777 /home/bob/IDB_TMP/json")
        while True:
            json_full_path_name=queue.get()
            print(json_full_path_name)
            
            self.json_file_read=open(json_full_path_name,encoding='utf-8').read()
            try:
                self.json_data=json.loads(self.json_file_read)
            except Exception as e:
            
                json_re=re.compile('([line]+) (\d+)')
                error_lines=copy.deepcopy(json_re.findall(str(e))[0][1])
            
                #객체 재생성
                json_file = open(json_full_path_name, 'r',encoding='utf-8')
                json_line_list=[]
                while True:
                    json_line=json_file.readline()
                    json_line_list.append(json_line)
                    if not json_line: break
                json_file.close()
                
                count=0
                json_file_re_read=open(json_full_path_name,'w',encoding='utf-8')
                for line_strings in json_line_list:
                    if count==int(error_lines) or count==int(error_lines)+1 or count==int(error_lines)-1:
                        count+=1
                        continue
                    json_file_re_read.write(line_strings)
                    count+=1
                json_file_re_read.close()
                
                
                json_file_read=open(json_full_path_name,encoding='utf-8').read()
                with open(json_full_path_name, 'w', encoding="utf-8") as make_file:
                        json.dump(json_file_read, make_file, ensure_ascii=False, indent="\t")

                try:
                    json_file_read=open(json_full_path_name,encoding='utf-8').read()
                    self.json_data=json.loads(json_full_path_name)
                except:
                    os.remove(json_full_path_name)
                    continue

            
            try:
                if glob.glob(os.path.join(self.idb_sample_full_path,self.json_data['pe_random'])+'*')[0]==[]:
                    os.remove(json_full_path_name)
                    continue
            except:
                os.remove(json_full_path_name)
                continue

            idb_file_name=os.path.basename(glob.glob(os.path.join(self.idb_sample_full_path,self.json_data['pe_random'])+'*')[0])
            idb_sample_full_path=os.path.join('/home/bob/IDB_TMP/Idb_Sample',idb_file_name)
            print(idb_sample_full_path)
            try:
                basic_block_result_list, constant_result_list, distance_result_list=self.idb_creator(idb_sample_full_path)
            except:
                print("None : {}".format(idb_sample_full_path))
                os.remove(json_full_path_name)
                continue
            if basic_block_result_list==None:
                print("Error :{}".format(self.json_data['pe_random']))
                os.remove(json_full_path_name)
                os.remove(idb_sample_full_path)
                continue

            M_insert=main_insert(self.json_data)
            M_insert.ssdeep_db_insert()
            FUNCTION_REPRE_LIST=M_insert.basicblock_extract(basic_block_result_list)
            M_insert.DATABASE_INSERT(FUNCTION_REPRE_LIST)
            M_insert.constant_value(constant_result_list)
            M_insert.RH_insert()
            M_insert.Distance(distance_result_list)
            M_insert.peinfo()
            M_insert.strings_insert()
            try:
                os.remove(json_full_path_name)
                os.remove(idb_sample_full_path)
            except:
                continue
        

if __name__=="__main__":
    queue=Queue()
    Mains=main_db_insert_cla(queue)
    Mains.queue_put()
    
    #Mains.main_db_insert_function(queue)
    
    
    proc_list=[]
    for _ in range(0,5):
        proc=Process(target=Mains.main_db_insert_function,args=(queue,))
        proc_list.append(proc)

    for proc in proc_list:
        proc.start()
    
    
