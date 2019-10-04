#내부 모듈
import threading
from multiprocessing import Process, current_process,Queue, Pool
import sys
import hashlib
import operator as op
import os
import json
import glob
import re
from datetime import datetime
import shutil
import time
#외부 모듈
import idb
import pefile
import ssdeep
#만든 모듈
import File_Information as FI
import Elastic
import ElasticQueryMaster
import Integrated_idb
import input_clustering as cl
import RH
import insert_db_pass_web
import M2push


class basic_block_values:
    def __init__(self,FILE_HASH,BASIC_BLOCK_INDEX,BASIC_BLOCK_OPCODE_ALL,Basic_Block_Detect,RESULT_HASH_OPCODE, RESULT_SSDEEP_HASHS,step5_Groups_Count,b_b_ngram_score_sum,
                                                                                                    BASIC_BLOCK_DISASM,BASIC_BLOCK_START,BASIC_BLOCK_END,Block_Id,BASIC_BLOCK_pseudo):
        self.FILE_HASH=FILE_HASH
        self.BASIC_BLOCK_INDEX=BASIC_BLOCK_INDEX
        self.BASIC_BLOCK_OPCODE_ALL=BASIC_BLOCK_OPCODE_ALL
        self.Basic_Block_Detect=Basic_Block_Detect
        self.RESULT_HASH_OPCODE=RESULT_HASH_OPCODE
        self.RESULT_SSDEEP_HASHS=RESULT_SSDEEP_HASHS
        self.step5_Groups_Count=step5_Groups_Count
        self.b_b_ngram_score_sum=b_b_ngram_score_sum
        self.BASIC_BLOCK_DISASM=BASIC_BLOCK_DISASM
        self.BASIC_BLOCK_START=BASIC_BLOCK_START
        self.BASIC_BLOCK_END=BASIC_BLOCK_END
        self.Block_Id=Block_Id
        self.pseudo_code=BASIC_BLOCK_pseudo


class idb_sim_creator:
    def __init__(self,json_data):
        self.json_data=json_data
        self.file_ssdeep_hash=self.json_data['pe_ssdeephash']
        self.file_sha256_hash=self.json_data['pe_sha256']
        self.groups=self.json_data['pe_groups']
        self.tags=self.json_data['pe_tags']
        
        self.idb_full_path='/home/bob/IDB_TMP/User_Sample/idb_samples'

        self.idb_file_name=os.path.basename(glob.glob(os.path.join(self.idb_full_path,self.json_data['pe_random'])+'*')[0])
        self.idb_sample_full_path=os.path.join('/home/bob/IDB_TMP/User_Sample/idb_samples',self.idb_file_name)
        shutil.copy(self.idb_sample_full_path,os.path.join('/home/bob/IDB_TMP/BackUp/idb_backup',self.idb_file_name))

        
    def idb_creator(self):
        with idb.from_file(self.idb_sample_full_path) as db:
            api=idb.IDAPython(db)
            basic_block_result_list, constant_result_list, distance_result_list = Integrated_idb.main(api,self.idb_sample_full_path)
            return basic_block_result_list, constant_result_list, distance_result_list


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

    
######################################################
mutex_file=open("mutex_strings_lists.txt",'r')
mutex_line=[]
while True:
    line = mutex_file.readline()
    if not line: break
    mutex_line.append(line.replace('\n',''))
mutex_file.close()
######################################################

def group_change(group_names):
    if 'Megniber'==group_names:
        Groups_Names="Magniber"
    elif 'GlobeImposter'==group_names:
        Groups_Names="Globelmposter"
    elif 'XOR_TRANSFORM_WILDCARD'==group_names or 'andarat' in group_names or 'bmdoor' in group_names or 'bmbot' in group_names or 'GoldenAxe' in group_names:
        Groups_Names="Andariel"
    elif 'akdoor' in group_names or 'DPRK' in group_names or 'Hwdoor' in group_names or 'joanap' in group_names or 'XwDoor' in group_names or 'NkDoor' in group_names:
        Groups_Names="Lazarus"
    elif 'Blackken' in group_names:
        Groups_Names="Scarcruft"
    else:
        Groups_Names=group_names
        
    return Groups_Names
    


class Sim_rate:
    def __init__(self,json_file):
        self.json_file=json_file
        #print(self.json_file)
        self.json_folder_full_path='/home/bob/IDB_TMP/json'
        self.idb_sample_full_path='/home/bob/IDB_TMP/User_Sample/idb_samples'
        
        self.json_file_read=open(self.json_file,encoding='utf-8').read()
        
        #FLAG 0 은 정상 |  1은 비정상
        self.flag=0
        
        try:
            self.json_data=json.loads(self.json_file_read)
        #이부분은 로드 에러 날때 해결하는 부분입니다. 별 신경쓰지 않아두됨 ^오^
        except Exception as e:
            #권한 상승안하면 에러 수정 안됨
            os.chmod("/home/bob/IDB_TMP/json", 4777)
            json_full_path_name=self.json_file
            
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
            
            json_file_read=open(json_full_path_name,encoding='utf-8').read()
            self.json_data=json.loads(json_full_path_name)

        try:
            if glob.glob(os.path.join(self.idb_sample_full_path,self.json_data['pe_random'])+'*')[0]==[]:
                #print("None : {}".format(self.json_file))
                m2push = M2push.M2push(url="https://m2lab.io", username="MASTER_ADMIN",api_key="900BB2D2300A947B90AB55B80D74A05376828EEEC816510CF2F1526AEEACCD6A")
                if m2push.send(self.json_data, type='linux') is False:
                    print("Fail.")
                os.remove(self.idb_sample_full_path)
                os.remove(os.path.join(self.json_folder_full_path,self.json_file))
                self.flag=1
        except:
            m2push = M2push.M2push(url="https://m2lab.io", username="MASTER_ADMIN",api_key="900BB2D2300A947B90AB55B80D74A05376828EEEC816510CF2F1526AEEACCD6A")
            if m2push.send(self.json_data, type='linux') is False:
                print("Fail.")
                self.flag=1
                os.remove(self.idb_sample_full_path)
                os.remove(os.path.join(self.json_folder_full_path,self.json_file))
            
  
        #print(self.json_data)
        self.file_ssdeep_hash=self.json_data['pe_ssdeephash']
        
        self.file_sha256_hash=self.json_data['pe_sha256']
        self.groups=self.json_data['pe_groups']
        self.tags=self.json_data['pe_tags']
        self.group_list_path=os.listdir('../Malware_Sample')
        
        self.idb_file_name=os.path.basename(glob.glob(os.path.join(self.idb_sample_full_path,self.json_data['pe_random'])+'*')[0])
        self.idb_sample_full_path=os.path.join('/home/bob/IDB_TMP/User_Sample/idb_samples',self.idb_file_name)
        self.sims=idb_sim_creator(self.json_data)

        try:
            self.basic_block_result_list, self.constant_result_list, self.distance_result_list = self.sims.idb_creator()
        except:
            print("Errors : {}".format(self.json_data['pe_random']))
            
            m2push = M2push.M2push(url="https://m2lab.io", username="MASTER_ADMIN",api_key="900BB2D2300A947B90AB55B80D74A05376828EEEC816510CF2F1526AEEACCD6A")
            if m2push.send(self.json_data, type='linux') is False:
                print("Fail.")
                
            #os.remove(self.idb_sample_full_path)
            #os.remove(os.path.join(self.json_folder_full_path,self.json_file))
            self.flag=1
            return None
        
        self.FUNCTION_REPRE_INSERT_LIST=self.sims.basicblock_extract(self.basic_block_result_list)
        self.STR_CLASS=FI.STRINGS()
        
    def Sim_rate_infos(self):
        return self.basic_block_result_list, self.constant_result_list, self.distance_result_list, self.FUNCTION_REPRE_INSERT_LIST
        
        
    def step_file_hash_matching(self):
        try:
            FILE_HASH=self.file_sha256_hash
        except:
            print(self.file_sha256_hash)
        cl.clustering().collect_hash(FILE_HASH)
        ela = ElasticQueryMaster.ElasticQueryMaster()
        query = {  
           "query":{  
              "match":{  
                 "sha256":FILE_HASH
              }
           }
        }
        file_hash_matching_result = ela.search(index="malware_info", query=query, query_cut_level=1)
        
        

        step0_1_Groups_Count={}
        for group in self.group_list_path:
            step0_1_Groups_Count[group]=0

        if len(file_hash_matching_result)>1:
            for TABLES_COLUM in file_hash_matching_result:
                Groups_Names=group_change(TABLES_COLUM['_source']['group'])
                step0_1_Groups_Count[Groups_Names]=op.add(step0_1_Groups_Count[Groups_Names],1)
                    
        file_hash_match_sum=list(step0_1_Groups_Count.values())
        file_hash_match_sum=sum(file_hash_match_sum)

        return step0_1_Groups_Count,file_hash_match_sum

    def step0_file_ssdeep_hash_matching(self):
        SAMPLE_SSDEEPS_HASH=self.file_ssdeep_hash
        cl.clustering().collect_ssdeep_hash(SAMPLE_SSDEEPS_HASH)
        matching_items = Elastic.get_matching_items_by_ssdeep(SAMPLE_SSDEEPS_HASH, 50)
        step0_Groups_Count={}
        for group in self.group_list_path:
            step0_Groups_Count[group]=0
            
        if len(matching_items)>=1:
            for items in matching_items:
                Groups_Names=group_change(items[4])

                step0_Groups_Count[Groups_Names]=op.add(step0_Groups_Count[Groups_Names],1)
                    
        step0_Groups_total=list(step0_Groups_Count.values())
        step0_Groups_total=sum(step0_Groups_total)
        #queue.put(step0_Groups_Count,step0_Groups_total)
        return step0_Groups_Count,step0_Groups_total
    
    
    
    def step1_repre_func(self):
        collect_HASH_OPCODE = {}
        step1_Groups_Count={}
        count=0
        for group in self.group_list_path:
            step1_Groups_Count[group]=0
        try:
            mutex_opcode_list=[]
            for BLOCK in self.FUNCTION_REPRE_INSERT_LIST:
                #샘플에 대한 블록 값들
                HASH_OPCODE=BLOCK[0] #블록에 대한 함수 대푯값
                SSDEEP_HASHS=BLOCK[1] #블록에 대한 SSDEEP 값
                #FILE_HASH=BLOCK[2] #파일 해시 값, 파일이름으로 됨에 주의
                #BASIC_BLOCK_INDEX=BLOCK[3] #
                #BASIC_BLOCK_OPCODE_ALL=BLOCK[4]
                
                
                collect_HASH_OPCODE[count]=HASH_OPCODE
                #1차적으로 함수 대푯값 검색
                RESULT_HASH_OPCODE = Elastic.search_everything("basic_block", "block_representative",HASH_OPCODE)
                Group_List=[]
                for TABLES_COLUM in RESULT_HASH_OPCODE:
                    Group_List.append(TABLES_COLUM['group'])
    
                Group_List=len(set(Group_List))
                if Group_List>1:
                    continue
                    
                
                #result에는 해당 HASH_OPCODE에 대한 Database 출력 리스트가 담겨있다.
                if RESULT_HASH_OPCODE:
                    for TABLES_COLUM in RESULT_HASH_OPCODE:
                        Groups_Names=group_change(TABLES_COLUM['group'])
                        
                        step1_Groups_Count[Groups_Names]=op.add(step1_Groups_Count[Groups_Names],1)
                        mutex_opcode_list.append(TABLES_COLUM['opcode'])
                count+=1
        except:
            pass
        repre_func_sum=list(step1_Groups_Count.values())
        repre_func_sum=sum(repre_func_sum)
        #queue.put(step1_Groups_Count,repre_func_sum)
        cl.clustering().collect_func_repre(collect_HASH_OPCODE)
        return step1_Groups_Count,repre_func_sum, mutex_opcode_list
        
            
    def step2_ssdeep_matching(self):
        count=0
        collect_ssdeep = {}
        step2_Groups_Count={}
        for group in self.group_list_path:
            step2_Groups_Count[group]=0

        for BLOCK in self.FUNCTION_REPRE_INSERT_LIST:
            #샘플에 대한 블록 값들
            HASH_OPCODE=BLOCK[0] #블록에 대한 함수 대푯값
            SSDEEP_HASHS=BLOCK[1] #블록에 대한 SSDEEP 값
            #FILE_HASH=BLOCK[2] #파일 해시 값, 파일이름으로 됨에 주의
            #BASIC_BLOCK_INDEX=BLOCK[3] #
            #BASIC_BLOCK_OPCODE_ALL=BLOCK[4]
            collect_ssdeep[count]=SSDEEP_HASHS
            count+=1
            RESULT_SSDEEP_HASHS = Elastic.search_everything("basic_block", "ssdeep",SSDEEP_HASHS)
            #print(RESULT_SSDEEP_HASHS)
            Group_List=[]
            for TABLES_COLUM in RESULT_SSDEEP_HASHS:
                Group_List.append(TABLES_COLUM['group'])
                
            Group_List=len(set(Group_List))
            if Group_List>1:
                continue
            
            
            if RESULT_SSDEEP_HASHS:
                for TABLES_COLUM in RESULT_SSDEEP_HASHS:
                    Groups_Names=group_change(TABLES_COLUM['group'])
                        
                    step2_Groups_Count[Groups_Names]=op.add(step2_Groups_Count[Groups_Names],1)
                    
        b_b_ssdeep_match_sum=list(step2_Groups_Count.values())
        b_b_ssdeep_match_sum=sum(b_b_ssdeep_match_sum)
        #for Groups_Names in step2_Groups_Count:
        #    step2_Groups_Count[Groups_Names]=(step2_Groups_Count[Groups_Names]/(b_b_ssdeep_match_sum*b_b_ssdeep_match_sum))
        
        #queue.put(step2_Groups_Count,b_b_ssdeep_match_sum)
        cl.clustering().collect_bb_ssdeep(collect_ssdeep)
        return step2_Groups_Count,b_b_ssdeep_match_sum

    
            
    def step3_ssdeep_compare(self,mutex_opcode_list):
        
        step3_Groups_Count={}
        for group in self.group_list_path:
            step3_Groups_Count[group]=0
        basic_block_mutex_list=[]
        for BLOCK in self.FUNCTION_REPRE_INSERT_LIST:
            #샘플에 대한 블록 값들
            HASH_OPCODE=BLOCK[0] #블록에 대한 함수 대푯값
            SSDEEP_HASHS=BLOCK[1] #블록에 대한 SSDEEP 값
            #FILE_HASH=BLOCK[2] #파일 해시 값, 파일이름으로 됨에 주의
            #BASIC_BLOCK_INDEX=BLOCK[3] #
            BASIC_BLOCK_OPCODE_ALL=BLOCK[4]
            if BASIC_BLOCK_OPCODE_ALL in basic_block_mutex_list:
                continue
            elif BASIC_BLOCK_OPCODE_ALL in mutex_opcode_list:
                continue
            else:
                basic_block_mutex_list.append(BASIC_BLOCK_OPCODE_ALL) 

            
            BASIC_BLOCK_SSDEEP_MATCHING_ITEMS = Elastic.find_basic_block_by_ssdeep(SSDEEP_HASHS, 30)
            if len(BASIC_BLOCK_SSDEEP_MATCHING_ITEMS)>1:
                GRADE_LIST=[]
                for ITMES in BASIC_BLOCK_SSDEEP_MATCHING_ITEMS: 
                    GRADE_LIST.append(ITMES['ssdeep_grade'])
                MAX_GRADE=max(GRADE_LIST)
                
                #ITEMS는 compare된 매칭 베이직 블록들 table은 basic_block 테이블
                for ITMES in BASIC_BLOCK_SSDEEP_MATCHING_ITEMS: 
                    if MAX_GRADE==ITMES['ssdeep_grade']:
                        Groups_Names=group_change(ITMES['group'])
                        step3_Groups_Count[Groups_Names]=op.add(step3_Groups_Count[Groups_Names],1)
                        
        b_b_ssdeep_compare_sum=list(step3_Groups_Count.values())
        b_b_ssdeep_compare_sum=sum(b_b_ssdeep_compare_sum)
        #queue.put(step3_Groups_Count,b_b_ssdeep_compare_sum)
        return step3_Groups_Count,b_b_ssdeep_compare_sum
    

    
    def step4_Rich_header(self):
        step4_Groups_Count={}
        for group in self.group_list_path:
            step4_Groups_Count[group]=0
        
        
        try:
            RH_result_object_list=RH.compare_clear_data(self.json_data)
            if RH_result_object_list==[]:
                return None
        except:
            return None
        
        
        for RH_object in RH_result_object_list:
            Groups_Names=RH_object.groups

        for RH_object in RH_result_object_list:
            Groups_Names=group_change(RH_object.groups)
                
            step4_Groups_Count[Groups_Names]=op.add(step4_Groups_Count[Groups_Names],1)
            
            if step4_Groups_Count[Groups_Names]!=0:
                print("\t Names : {}".format(Groups_Names))
                print("\t Matching Values : {}".format(step4_Groups_Count[Groups_Names]))
                print("-----------------------------------------------------------")
        #queue.put(step4_Groups_Count)
        return step4_Groups_Count
    

    
    def step5_ngram_score(self,mutex_opcode_list):
        step5_Groups_Count={}
        count=0
        collect_opi={}
        for group in self.group_list_path:
            step5_Groups_Count[group]=0
        basic_block_mutex_list=[]
        for BLOCK in self.FUNCTION_REPRE_INSERT_LIST:
            #샘플에 대한 블록 값들
            HASH_OPCODE=BLOCK[0] #블록에 대한 함수 대푯값
            SSDEEP_HASHS=BLOCK[1] #블록에 대한 SSDEEP 값
            #FILE_HASH=BLOCK[2] #파일 해시 값, 파일이름으로 됨에 주의
            #BASIC_BLOCK_INDEX=BLOCK[3] #
            BASIC_BLOCK_OPCODE_ALL=BLOCK[4]

            if BASIC_BLOCK_OPCODE_ALL in basic_block_mutex_list:
                continue
            elif BASIC_BLOCK_OPCODE_ALL in mutex_opcode_list:
                continue
            else:
                basic_block_mutex_list.append(BASIC_BLOCK_OPCODE_ALL) 
            
            collect_opi[count]=BASIC_BLOCK_OPCODE_ALL
            count+=1
            ela = ElasticQueryMaster.ElasticQueryMaster()
            query = {  
               "query":{  
                  "match":{  
                     "opcode":BASIC_BLOCK_OPCODE_ALL
                  }
               }
            }
            ngram_search_result_list = ela.search(index="basic_block", query=query, query_cut_level=1)
            score_totals=0
            score={}
            if len(ngram_search_result_list)>1:
                for ngram_search_result_object in ngram_search_result_list:
                    Groups_Names=group_change(ngram_search_result_object['_source']['group'])
                        
                    try:
                        if score[Groups_Names]<ngram_search_result_object['_score']/len(ngram_search_result_object['_source']['opcode']):
    
                            score[Groups_Names]=ngram_search_result_object['_score']/len(ngram_search_result_object['_source']['opcode'])
                    except:
                        score[Groups_Names]=ngram_search_result_object['_score']/len(ngram_search_result_object['_source']['opcode'])

                score_sorted=sorted(score.items(),key=op.itemgetter(1),reverse=True)
                for score_object in score_sorted[0:2]:
                    score_totals=op.add(score_totals,score_object[1])
                if len(score_sorted)==1:
                    num1_max_group_simil=int("{:.0%}".format((score_sorted[0][1]/score_totals)).replace("%",""))
                    step5_Groups_Count[score_sorted[0][0]]=op.add(step5_Groups_Count[score_sorted[0][0]],1)
                else:
                    num1_max_group_simil=int("{:.0%}".format((score_sorted[0][1]/score_totals)).replace("%",""))
                    num2_max_group_simil=int("{:.0%}".format((score_sorted[1][1]/score_totals)).replace("%",""))
                    if op.sub(num1_max_group_simil,num2_max_group_simil)>=12:     
                        step5_Groups_Count[score_sorted[0][0]]=op.add(step5_Groups_Count[score_sorted[0][0]],1)
                                                                                
        b_b_ngram_score_sum=list(step5_Groups_Count.values())
        b_b_ngram_score_sum=sum(b_b_ngram_score_sum)
        #queue.put(step5_Groups_Count,b_b_ngram_score_sum)
        cl.clustering().collect_opi(collect_opi)
        return step5_Groups_Count,b_b_ngram_score_sum    

 
 
    def step6_constant_value_score(self):
        score_totals=0
        score={}
        step6_Groups_Count={}
        collect_con={}
        count=0
        for group in self.group_list_path:
            step6_Groups_Count[group]=0
        
        ela = ElasticQueryMaster.ElasticQueryMaster()
        constant_sim_result_list=self.constant_result_list
        cl.clustering().collect_constant_value(constant_sim_result_list)
        for constant_sim_result in constant_sim_result_list:
            constant_value=' '.join(constant_sim_result)
            
            query = {  
               "query":{  
                  "match":{  
                     "constant_value":constant_value
                  }
               }
            }
            
            try:
                constant_search_result_list = ela.search(index="constant-value", query=query, query_cut_level=1)
            except:
                print(query)
                continue
            
            score_totals=0
            score={}
            if len(constant_search_result_list)>1:
                for constant_search_result_object in constant_search_result_list:
                    Groups_Names=group_change(constant_search_result_object['_source']['group'])
                        
                        
                    try:
                        if score[Groups_Names]<constant_search_result_object['_score']/len(constant_search_result_object['_source']['constant_value']):
                            score[Groups_Names]=constant_search_result_object['_score']/len(constant_search_result_object['_source']['constant_value'])
                    except:
                        score[Groups_Names]=constant_search_result_object['_score']/len(constant_search_result_object['_source']['constant_value'])

                score_sorted=sorted(score.items(),key=op.itemgetter(1),reverse=True)
                for score_object in score_sorted[0:2]:
                    score_totals=op.add(score_totals,score_object[1])
                if len(score_sorted)==1:
                    num1_max_group_simil=int("{:.0%}".format((score_sorted[0][1]/score_totals)).replace("%",""))
                    step6_Groups_Count[score_sorted[0][0]]=op.add(step6_Groups_Count[score_sorted[0][0]],1)
                else:
                    num1_max_group_simil=int("{:.0%}".format((score_sorted[0][1]/score_totals)).replace("%",""))
                    num2_max_group_simil=int("{:.0%}".format((score_sorted[1][1]/score_totals)).replace("%",""))
                    if op.sub(num1_max_group_simil,num2_max_group_simil)>=12:     
                        step6_Groups_Count[score_sorted[0][0]]=op.add(step6_Groups_Count[score_sorted[0][0]],1)
            
        constant_value_score_sum=list(step6_Groups_Count.values())
        constant_value_score_sum=sum(constant_value_score_sum)
        #queue.put(step6_Groups_Count,constant_value_score_sum)
        return step6_Groups_Count,constant_value_score_sum

    
    def step7_peinfos(self):
        step7_Groups_Count={}
        for group in self.group_list_path:
            step7_Groups_Count[group]=0
                
        #pdb
        pdb_dic_data=self.json_data['pe_pdb']
        pdb_name=pdb_dic_data['Name']
        pdb_age=pdb_dic_data['Age']
        pdb_guid=pdb_dic_data['GUID']
        pdb_path=pdb_dic_data['Pdbpath']
        #imphash
        imp_hash_data=self.json_data['pe_imphash']
        #codesign
        code_sign_data=self.json_data['pe_codesign']
        
        #create query
        should_query=[]
        #pdb query
        if pdb_name!="None":
            should_query.append({ "match": { "pdb_name" :pdb_name}})
        if pdb_guid!="None":
            should_query.append({ "match": { "pdb_guid" :pdb_guid }})
        if pdb_path!="None":
            should_query.append({ "match": { "pdb_path" :pdb_path }})
        #codesign query
        if code_sign_data!="None" :
            should_query.append({ "match": { "codesign" :code_sign_data}})
        #imphash query
        if imp_hash_data!="":
            should_query.append({ "match": { "imphash" :imp_hash_data}})
        
        
        #should_query=[{'match': {'pdb_name': 'None'}}, {'match': {'pdb_guid': 'None'}}, {'match': {'pdb_path': 'None'}},{'match': {'codesign': ''}}, {'match': {'imphash': '4B18F870F82CB38D371C4AC7664CA12F'}}]
        ###########################################elastic search###########################
        if len(should_query)>0:
            ela = ElasticQueryMaster.ElasticQueryMaster()
            query = {  
                "query":{
                    "bool": {
                      "should": should_query
                    }
                }
            }
            peinfo_search_result_list = ela.search(index="peinfos", query=query, query_cut_level=1)
            print("PE Infoe : {}".format(query))
            ####################################################################################

            if len(peinfo_search_result_list)>0:
                for peinfo_result_object in peinfo_search_result_list:
                    Groups_Names=group_change(peinfo_result_object['_source']['group'])
                        
                    
                    
                    if pdb_name!="None" or len(peinfo_result_object['_source']["pdb_name"])>4:
                        if pdb_name==peinfo_result_object['_source']["pdb_name"]:
                            step7_Groups_Count[Groups_Names]=op.add(step7_Groups_Count[Groups_Names],1)
                    if pdb_guid!="None"or len(peinfo_result_object['_source']["pdb_guid"])>4:
                        if pdb_guid==peinfo_result_object['_source']["pdb_guid"]:
                            step7_Groups_Count[Groups_Names]=op.add(step7_Groups_Count[Groups_Names],1)
                    if code_sign_data!="None"or len(peinfo_result_object['_source']["codesign"])>4:
                        if code_sign_data==peinfo_result_object['_source']["codesign"]:
                            step7_Groups_Count[Groups_Names]=op.add(step7_Groups_Count[Groups_Names],1)
                    if imp_hash_data!="None" or len(peinfo_result_object['_source']["imphash"])>4:
                        if imp_hash_data==peinfo_result_object['_source']["imphash"]:
                            step7_Groups_Count[Groups_Names]=op.add(step7_Groups_Count[Groups_Names],1)
                    if pdb_path!="None" or len(peinfo_result_object['_source']["pdb_path"])>4:
                        if pdb_path==peinfo_result_object['_source']["pdb_path"]:
                            step7_Groups_Count[Groups_Names]=op.add(step7_Groups_Count[Groups_Names],1)
                        
                        
                del(peinfo_search_result_list)


        if pdb_path=="None":
            peinfo_score_sum=list(step7_Groups_Count.values())
            peinfo_score_sum=sum(peinfo_score_sum)
            #print(step7_Groups_Count,peinfo_score_sum)
            return step7_Groups_Count, peinfo_score_sum
            
        score_totals=0
        score={}
        query = {  
           "query":{  
              "match":{  
                 "pdb_path":pdb_path
              }
           }
        }
        peinfo_search_result_list = ela.search(index="peinfos", query=query, query_cut_level=1)
        print("PDB Path {}".format(query))
        
        if len(peinfo_search_result_list)>0:
            for peinfo_result_object in peinfo_search_result_list:
                Groups_Names=group_change(peinfo_result_object['_source']['group'])
                if len(peinfo_result_object['_source']["pdb_path"])<4:
                    continue
                
                try:
                    if score[Groups_Names]<peinfo_result_object['_score']/len(peinfo_result_object['_source']['pdb_path']):
                        score[Groups_Names]=peinfo_result_object['_score']/len(peinfo_result_object['_source']['pdb_path'])
                except:
                    score[Groups_Names]=peinfo_result_object['_score']/len(peinfo_result_object['_source']['pdb_path'])


            score_sorted=sorted(score.items(),key=op.itemgetter(1),reverse=True)
            for score_object in score_sorted[0:2]:
                score_totals=op.add(score_totals,score_object[1])

            if len(score_sorted)==1:
                step7_Groups_Count[score_sorted[0][0]]=op.add(step7_Groups_Count[score_sorted[0][0]],1)
            else:
                num1_max_group_simil=int("{:.0%}".format((score_sorted[0][1]/score_totals)).replace("%",""))
                num2_max_group_simil=int("{:.0%}".format((score_sorted[1][1]/score_totals)).replace("%",""))
                if op.sub(num1_max_group_simil,num2_max_group_simil)>=5:
                    step7_Groups_Count[score_sorted[0][0]]=op.add(step7_Groups_Count[score_sorted[0][0]],10)
                
                
            peinfo_score_sum=list(step7_Groups_Count.values())
            peinfo_score_sum=sum(peinfo_score_sum)
            #print(step7_Groups_Count,peinfo_score_sum)
            return step7_Groups_Count, peinfo_score_sum
        else:
            peinfo_score_sum=list(step7_Groups_Count.values())
            peinfo_score_sum=sum(peinfo_score_sum)
            return step7_Groups_Count, peinfo_score_sum
    
    def step8_calling_distance(self):
        step8_Groups_Count={}
        for group in self.group_list_path:
            step8_Groups_Count[group]=0
        
        distance_result=self.distance_result_list
        if distance_result==None or distance_result==0 or str(distance_result)=="nan" or str(distance_result)=='NaN':
            distance_value_score_sum=list(step8_Groups_Count.values())
            distance_value_score_sum=sum(distance_value_score_sum)
            return step8_Groups_Count,distance_value_score_sum
        
        #정수형으로 변환
        try:
            distance_result=int(distance_result)
        except:
            pass
        
        ela = ElasticQueryMaster.ElasticQueryMaster()
        print("GTE : {} ".format(distance_result+distance_result*0.025))
        print("Middle : {} ".format(distance_result))
        print("LTE : {} ".format(distance_result-distance_result*0.025))
        query={
            "query": {
                "range" : {
                    "distance" : {
                        "gte" : distance_result-distance_result*0.015,
                        "lte" : distance_result+distance_result*0.015,
                        "boost" : 1.0
                    }
                }
            }
        }
        try:
            calling_ditance_result_list = ela.search(index="calling-distance", query=query, query_cut_level=1)
        except:
            distance_value_score_sum=list(step8_Groups_Count.values())
            distance_value_score_sum=sum(distance_value_score_sum)
            return step8_Groups_Count,distance_value_score_sum
            
        #print("Ela Values : {}".format(calling_ditance_result_list))
        
        for calling_result_object in calling_ditance_result_list:
            calling_ditance=calling_result_object['_source']['distance']
            
            if distance_result in range(distance_result-int(calling_ditance*0.015),distance_result+int(calling_ditance*0.015)):
                Groups_Names=group_change(calling_result_object['_source']['group'])
                    
                    
                step8_Groups_Count[Groups_Names]=op.add(step8_Groups_Count[Groups_Names],1)
                
        distance_value_score_sum=list(step8_Groups_Count.values())
        distance_value_score_sum=sum(distance_value_score_sum)
        return step8_Groups_Count,distance_value_score_sum
    
    '''
    #추가 예정 18-11-19
    def step9_strings_score(self,json_data,strings_Queue):
        step9_Groups_Count={}
        for group in os.listdir('/home/bob/Malware_Sample'):
            step9_Groups_Count[group]=0

        #strings
        strings_lists=json_data['pe_strings']
        strings_ngram_list=[]
        
        ipaddress_re=re.compile('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
        email_re=re.compile('^[a-zA-Z0-9+-_.]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
        url_re=re.compile(r'^(?:(?:https|ftp|www)://)(?:\S+(?::\S*)?@)?(?:(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,})))(?::\d{2,5})?(?:/[^\s]*)?$')

        mutex1=re.compile("[@]")
        mutex2=re.compile("[?]")
        mutex3=re.compile("[=]")
        mutex4=re.compile("[\w]")
        mutex5=re.compile("[\W]")
        
        
        sample_str_list=[]
        
        ela = ElasticQueryMaster.ElasticQueryMaster()
        
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
    
    
            #엘라 에러 방지 (최대 글자 제한)
            if index % 15 == 0:
                sample_strings=' '.join(sample_str_list)
                if len(sample_strings)<3:
                    continue
                
                query = {  
                   "query":{  
                      "match":{  
                         "strings":sample_strings
                      }
                   }
                }

                strings_ngram_list = strings_ngram_list+ela.search(index="pe_strings", query=query, query_cut_level=1)
                sample_str_list=[]
                
    
        sample_strings=' '.join(sample_str_list)
        if len(sample_strings)<3:
            b_b_ngram_score_sum=list(step9_Groups_Count.values())
            b_b_ngram_score_sum=sum(b_b_ngram_score_sum)
            #cl.clustering().collect_opi(collect_opi)
            return step9_Groups_Count,b_b_ngram_score_sum
        
        query = {  
           "query":{  
              "match":{  
                 "strings":sample_strings
              }
           }
        }
        try:
            strings_ngram_list = strings_ngram_list+ela.search(index="pe_strings", query=query, query_cut_level=1)
        except:
            print("Strings ela Error")
        #search한 list를 모두 더함

        score_totals=0
        score={}
        if len(strings_ngram_list)>1:
            for strings_search_result_object in strings_ngram_list:
                if 'Megniber'==strings_search_result_object['_source']['group']:
                    Groups_Names="Magniber"
                elif 'GlobeImposter'==strings_search_result_object['_source']['group']:
                    Groups_Names="Globelmposter"
                elif 'XOR_TRANSFORM_WILDCARD'==strings_search_result_object['_source']['group'] or 'andarat' in strings_search_result_object['_source']['group'] or 'bmdoor' in strings_search_result_object['_source']['group'] or 'bmbot' in strings_search_result_object['_source']['group']:
                    Groups_Names="Andariel"
                elif 'akdoor' in strings_search_result_object['_source']['group'] or 'DPRK' in strings_search_result_object['_source']['group'] or 'Hwdoor' in strings_search_result_object['_source']['group'] or 'joanap' in strings_search_result_object['_source']['group'] or 'XwDoor' in strings_search_result_object['_source']['group'] or 'NkDoor' in strings_search_result_object['_source']['group']:
                    Groups_Names="Lazarus"
                elif 'Blackken' in strings_search_result_object['_source']['group']:
                    Groups_Names="Scarcruft"
                else:
                    Groups_Names=strings_search_result_object['_source']['group']
                    
                    
                    
                try:
                    if score[Groups_Names]<strings_search_result_object['_score']/len(strings_search_result_object['_source']['strings']):

                        score[Groups_Names]=strings_search_result_object['_score']/len(strings_search_result_object['_source']['strings'])
                except:
                    score[Groups_Names]=strings_search_result_object['_score']/len(strings_search_result_object['_source']['strings'])

            score_sorted=sorted(score.items(),key=op.itemgetter(1),reverse=True)
            for score_object in score_sorted[0:2]:
                score_totals=op.add(score_totals,score_object[1])
            if len(score_sorted)==1:
                num1_max_group_simil=int("{:.0%}".format((score_sorted[0][1]/score_totals)).replace("%",""))
                step9_Groups_Count[score_sorted[0][0]]=op.add(step9_Groups_Count[score_sorted[0][0]],1)
            else:
                num1_max_group_simil=int("{:.0%}".format((score_sorted[0][1]/score_totals)).replace("%",""))
                num2_max_group_simil=int("{:.0%}".format((score_sorted[1][1]/score_totals)).replace("%",""))
                if op.sub(num1_max_group_simil,num2_max_group_simil)>=5:     
                    step9_Groups_Count[score_sorted[0][0]]=op.add(step9_Groups_Count[score_sorted[0][0]],1)
                                                                            
        b_b_ngram_score_sum=list(step9_Groups_Count.values())
        b_b_ngram_score_sum=sum(b_b_ngram_score_sum)
        #cl.clustering().collect_opi(collect_opi)
        strings_Queue((step9_Groups_Count,b_b_ngram_score_sum))
        return step9_Groups_Count,b_b_ngram_score_sum
        '''
    
    
    
    
    
    
    
    def Search_Block(self,BASIC_BLOCK_OPCODE_ALL,BASIC_BLOCK_OPCODE):
        Basic_block_id=None
        OPCODE_HEX_LIST=[]
        SSDEEP_HASHS=ssdeep.hash(BASIC_BLOCK_OPCODE_ALL,encoding='utf-8')

        for OPCODE_HEX in BASIC_BLOCK_OPCODE:
            OPCODE_HEX_LIST.append(self.STR_CLASS.STR_HEX_COVERTER(OPCODE_HEX))
        BASIC_BLOCK_OPCODE_HEX=self.STR_CLASS.STR_ADD(OPCODE_HEX_LIST)

        #베이직 블록 내 opcode에 대한 xor 연산 후 해시 화 -> 함수 대푯값 선정
        HASH_OPCODE=hashlib.sha256(str(BASIC_BLOCK_OPCODE_HEX).encode()).hexdigest()

        #함수 대푯값
        RESULT_HASH_OPCODE = Elastic.search_everything("basic_block", "block_representative",HASH_OPCODE)
        Group_List=[]
        for TABLES_COLUM in RESULT_HASH_OPCODE:
            Groups_Names=group_change(TABLES_COLUM['group'])
            Basic_block_id=TABLES_COLUM['_id']
            
            Group_List.append(Groups_Names)

        Group_List=len(set(Group_List))
        if Group_List>1:
            Basic_block_id=None
            RESULT_HASH_OPCODE=None
        #ssdeep 값

        RESULT_SSDEEP_HASHS = Elastic.search_everything("basic_block", "ssdeep",SSDEEP_HASHS)
        Group_List=[]
        for TABLES_COLUM in RESULT_SSDEEP_HASHS:
            Groups_Names=group_change(TABLES_COLUM['group'])
            Basic_block_id=TABLES_COLUM['_id']
                
            Group_List.append(Groups_Names)
        
        Group_List=len(set(Group_List))
        if Group_List>1:
            Basic_block_id=None
            RESULT_SSDEEP_HASHS=None
        return RESULT_HASH_OPCODE, RESULT_SSDEEP_HASHS, Basic_block_id
    
    
    
    def basic_block_index_infos(self):
        self.Opcode_Indexing_result=[]
        BASIC_BLOCK_INDEX=0
        MUTEX_LIST=[]

        basic_block_mutex_list=[]
        for FUNC_BLOCK in self.basic_block_result_list:
            
            for BASIC_BLOCK in FUNC_BLOCK:
                BASIC_BLOCK_OPCODE_ALL=' '.join(BASIC_BLOCK.opcode)

                if BASIC_BLOCK_OPCODE_ALL in basic_block_mutex_list:
                    continue
                else:
                    basic_block_mutex_list.append(BASIC_BLOCK_OPCODE_ALL) 


                Basic_Block_Detect=False
                RESULT_HASH_OPCODE, RESULT_SSDEEP_HASHS,Block_Id=self.Search_Block(BASIC_BLOCK_OPCODE_ALL,BASIC_BLOCK.opcode)
                if RESULT_HASH_OPCODE!=None:
                    if len(RESULT_HASH_OPCODE)>=1:
                        Basic_Block_Detect=True

                if RESULT_SSDEEP_HASHS!=None:
                    if len(RESULT_SSDEEP_HASHS)>=1:
                        Basic_Block_Detect=True

                step5_Groups_Count,b_b_ngram_score_sum =basic_block_step5_ngram_score(BASIC_BLOCK_OPCODE_ALL)
                self.Opcode_Indexing_result.append(basic_block_values(self.file_sha256_hash,
                                                                BASIC_BLOCK_INDEX,
                                                                BASIC_BLOCK_OPCODE_ALL,
                                                                Basic_Block_Detect,
                                                                RESULT_HASH_OPCODE,
                                                                RESULT_SSDEEP_HASHS,
                                                                step5_Groups_Count,
                                                                b_b_ngram_score_sum,
                                                                BASIC_BLOCK.disasms,
                                                                BASIC_BLOCK.startaddr,
                                                                BASIC_BLOCK.endaddr,
                                                                Block_Id,
                                                                BASIC_BLOCK.pseudo))
                BASIC_BLOCK_INDEX=BASIC_BLOCK_INDEX+1
            del(BASIC_BLOCK_OPCODE_ALL)
        #(self.Opcode_Indexing_result)
        #self.Opcode_Indexing_conduct(self.Opcode_Indexing_result)
        #queue.put(self.Opcode_Indexing_result)
        return self.Opcode_Indexing_result
    
    def Opcode_Indexing_conduct(self,Opcode_Indexing_result):
        FILE_HASH=self.file_sha256_hash
        basic_blocK_dict={}
        for indexing_values in Opcode_Indexing_result:
            if indexing_values.Basic_Block_Detect==True:
                group_list=[]
                if indexing_values.RESULT_HASH_OPCODE:
                    for TABLES_COLUM in indexing_values.RESULT_HASH_OPCODE:
                        Groups_Names=group_change(TABLES_COLUM['group'])
                        group_list.append(Groups_Names)
                        
                if indexing_values.RESULT_SSDEEP_HASHS:
                    for TABLES_COLUM in indexing_values.RESULT_SSDEEP_HASHS:
                        Groups_Names=group_change(TABLES_COLUM['group'])
                            
                        group_list.append(Groups_Names)

                        
                    group_list=list(set(group_list))
                    step5_Groups_Count_sort_list=sorted(indexing_values.step5_Groups_Count.items(),key=op.itemgetter(1),reverse=True)
                    step5_Groups_Count_sort_list=dict(step5_Groups_Count_sort_list)
                    for Groups_Names in step5_Groups_Count_sort_list:
                        if Groups_Names in group_list:
                            step5_Groups_Count_sort_list[Groups_Names]=1


                    step5_Groups_Count_sort_list=sorted(step5_Groups_Count_sort_list.items(),key=op.itemgetter(1),reverse=True)
                    num1_max_group_simil=int("{:.0%}".format(step5_Groups_Count_sort_list[0][1]).replace('%',''))
                    num2_max_group_simil=int("{:.0%}".format(step5_Groups_Count_sort_list[1][1]).replace('%',''))
                    step5_Groups_Count_sort_list=dict(step5_Groups_Count_sort_list)

                    for Groups_Names in step5_Groups_Count_sort_list:
                        if Groups_Names in group_list:
                            sim_score=int("{:.0%}".format(step5_Groups_Count_sort_list[Groups_Names]).replace("%",""))
                            if sim_score==0:
                                continue
                            step5_Groups_Count_sort_list[Groups_Names]=step5_Groups_Count_sort_list[Groups_Names]
                        else:
                            sim_score=int("{:.0%}".format(step5_Groups_Count_sort_list[Groups_Names]).replace("%",""))
                            if sim_score==0:
                                continue
                            step5_Groups_Count_sort_list[Groups_Names]=step5_Groups_Count_sort_list[Groups_Names]
                            
                    basic_blocK_dict[indexing_values.BASIC_BLOCK_INDEX]={'basic_block_start_address':hex(indexing_values.BASIC_BLOCK_START),
                                                                       'basic_block_end_address':hex(indexing_values.BASIC_BLOCK_END),
                                                                       'BLOCK_hash_matched':indexing_values.Basic_Block_Detect,
                                                                       'basic_blcok_opcode_disasm':indexing_values.BASIC_BLOCK_DISASM,
                                                                       'basic_block_opcode_all':indexing_values.BASIC_BLOCK_OPCODE_ALL,
                                                                       'basic_block_opcode':indexing_values.RESULT_HASH_OPCODE,
                                                                       'basic_block_ssdeep_hash':indexing_values.RESULT_SSDEEP_HASHS,
                                                                       'group_similarity':step5_Groups_Count_sort_list,
                                                                       'BasicBlockId':indexing_values.Block_Id,
                                                                       'basic_block_pseudo_code':indexing_values.pseudo_code
                                                                        }



            else:

                step5_Groups_Count_sort_list=sorted(indexing_values.step5_Groups_Count.items(),key=op.itemgetter(1),reverse=True)
                num1_max_group_simil=int("{:.0%}".format(step5_Groups_Count_sort_list[0][1]).replace('%',''))
                num2_max_group_simil=int("{:.0%}".format(step5_Groups_Count_sort_list[1][1]).replace('%',''))
                step5_Groups_Count_sort_list=dict(step5_Groups_Count_sort_list)
                if op.sub(num1_max_group_simil,num2_max_group_simil)>=10:
                    for Groups_Names in step5_Groups_Count_sort_list:
                        sim_score=int("{:.0%}".format(step5_Groups_Count_sort_list[Groups_Names]).replace("%",""))
                        if sim_score==0:
                            continue
                        step5_Groups_Count_sort_list[Groups_Names]=step5_Groups_Count_sort_list[Groups_Names]
                basic_blocK_dict[indexing_values.BASIC_BLOCK_INDEX]={'basic_block_start_address':hex(indexing_values.BASIC_BLOCK_START),
                                                                   'basic_block_end_address':hex(indexing_values.BASIC_BLOCK_END),
                                                                   'BLOCK_hash_matched':indexing_values.Basic_Block_Detect,
                                                                   'basic_blcok_opcode_disasm':indexing_values.BASIC_BLOCK_DISASM,
                                                                   'basic_block_opcode_all':indexing_values.BASIC_BLOCK_OPCODE_ALL,
                                                                   'group_similarity':step5_Groups_Count_sort_list,
                                                                   'BasicBlockId':indexing_values.Block_Id,
                                                                   'basic_block_pseudo_code':indexing_values.pseudo_code
                                                                    }
        return basic_blocK_dict


        
def basic_block_step5_ngram_score(BASIC_BLOCK_OPCODE_ALL):
    step5_Groups_Count={}
    group_list_path=os.listdir('../Malware_Sample')
    for group in group_list_path:
        step5_Groups_Count[group]=0

    ela = ElasticQueryMaster.ElasticQueryMaster()
    query = {  
       "query":{  
          "match":{  
             "opcode":BASIC_BLOCK_OPCODE_ALL
          }
       }
    }
    
    GRADE_LIST=[]
    group_count=0
    ngram_search_result_list = ela.search(index="basic_block", query=query, query_cut_level=1)
    if len(ngram_search_result_list)>=1:
        #각 그룹 내 상위 점수 추출
        for ngram_search_object in ngram_search_result_list:
            Groups_Names=group_change(ngram_search_object['_source']['group'])
            try:
                if ngram_search_object['_score']>step5_Groups_Count[Groups_Names]:
                    step5_Groups_Count[Groups_Names]=ngram_search_object['_score']
                #step5_Groups_Count[Groups_Names]=op.add(step5_Groups_Count[Groups_Names],ngram_search_object['_score'])
            except:
                continue
        b_b_ngram_score_sum=list(step5_Groups_Count.values())
        b_b_ngram_score_sum=int(sum(b_b_ngram_score_sum))

        
        #그룹 내 상위 값을 분자로, 전체 그룹 내 상위 점수를 분모로 한 뒤 이를 퍼센트화 한다.
        #print("Group Total : {}".format(b_b_ngram_score_sum))
        for Groups_Names in step5_Groups_Count:
            #print("\t{} Count : {} ".format(Groups_Names,int(step5_Groups_Count[Groups_Names])))
            step5_Groups_Count[Groups_Names]=int(step5_Groups_Count[Groups_Names])/b_b_ngram_score_sum

    return step5_Groups_Count,b_b_ngram_score_sum
    


def step9_strings_score(json_data,strings_Queue):
    step9_Groups_Count={}
    for group in os.listdir('/home/bob/Malware_Sample'):
        step9_Groups_Count[group]=0

    #strings
    strings_lists=json_data['pe_strings']

    strings_ngram_list=[]
    
    ipaddress_re=re.compile('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    email_re=re.compile('^[a-zA-Z0-9+-_.]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
    url_re=re.compile(r'^(?:(?:https|ftp|www)://)(?:\S+(?::\S*)?@)?(?:(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,})))(?::\d{2,5})?(?:/[^\s]*)?$')

    mutex1=re.compile("[@]")
    mutex2=re.compile("[?]")
    mutex3=re.compile("[=]")
    mutex4=re.compile("[\w]")
    mutex5=re.compile("[\W]")
    
    
    sample_str_list=[]
    
    ela = ElasticQueryMaster.ElasticQueryMaster()
    max_time_end = time.time() + (60 * 2)
    for index,sample_str in enumerate(strings_lists):
        if time.time() > max_time_end:
            break
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


        #엘라 에러 방지 (최대 글자 제한)
        if index % 15 == 0:
            sample_strings=' '.join(sample_str_list)
            if len(sample_strings)<3:
                continue
            
            query = {  
               "query":{  
                  "match":{  
                     "strings":sample_strings
                  }
               }
            }

            strings_ngram_list = strings_ngram_list+ela.search(index="pe_strings", query=query, query_cut_level=1)
            sample_str_list=[]
            

    sample_strings=' '.join(sample_str_list)
    if len(sample_strings)<3:
        b_b_ngram_score_sum=list(step9_Groups_Count.values())
        b_b_ngram_score_sum=sum(b_b_ngram_score_sum)
        #cl.clustering().collect_opi(collect_opi)
        strings_Queue.put((step9_Groups_Count,b_b_ngram_score_sum))
        return step9_Groups_Count,b_b_ngram_score_sum
    
    query = {  
       "query":{  
          "match":{  
             "strings":sample_strings
          }
       }
    }
    #print(sample_strings)
    try:
        strings_ngram_list = strings_ngram_list+ela.search(index="pe_strings", query=query, query_cut_level=1)
    except:
        print("Strings ela Error")
    #search한 list를 모두 더함

    score_totals=0
    score={}
    if len(strings_ngram_list)>1:
        for strings_search_result_object in strings_ngram_list:
            Groups_Names=group_change(strings_search_result_object['_source']['group'])
                
                
                
            try:
                if score[Groups_Names]<strings_search_result_object['_score']/len(strings_search_result_object['_source']['strings']):

                    score[Groups_Names]=strings_search_result_object['_score']/len(strings_search_result_object['_source']['strings'])
            except:
                score[Groups_Names]=strings_search_result_object['_score']/len(strings_search_result_object['_source']['strings'])

        score_sorted=sorted(score.items(),key=op.itemgetter(1),reverse=True)
        for score_object in score_sorted[0:2]:
            score_totals=op.add(score_totals,score_object[1])
        if len(score_sorted)==1:
            num1_max_group_simil=int("{:.0%}".format((score_sorted[0][1]/score_totals)).replace("%",""))
            step9_Groups_Count[score_sorted[0][0]]=op.add(step9_Groups_Count[score_sorted[0][0]],1)
        else:
            num1_max_group_simil=int("{:.0%}".format((score_sorted[0][1]/score_totals)).replace("%",""))
            num2_max_group_simil=int("{:.0%}".format((score_sorted[1][1]/score_totals)).replace("%",""))
            if op.sub(num1_max_group_simil,num2_max_group_simil)>=5:     
                step9_Groups_Count[score_sorted[0][0]]=op.add(step9_Groups_Count[score_sorted[0][0]],1)
                                                                        
    b_b_ngram_score_sum=list(step9_Groups_Count.values())
    b_b_ngram_score_sum=sum(b_b_ngram_score_sum)
    #cl.clustering().collect_opi(collect_opi)
    strings_Queue.put((step9_Groups_Count,b_b_ngram_score_sum))
    return step9_Groups_Count,b_b_ngram_score_sum



def Print_Rate(step,step_group_total,flag):
    Groups_Count={}
    group_list_path=os.listdir('../Malware_Sample')
    for group in group_list_path:
        Groups_Count[group]=0
    if flag==0:
        if step_group_total>=1:
            try:
                for names in step:
                    Groups_Count[names]=int('{:.0%}'.format(step[names]/step_group_total).replace('%',''))
                    if Groups_Count[names]==0:
                        continue
            except ZeroDivisionError:
                pass

    elif flag==1:
        try:
            for names in step:
                Groups_Count[names]=int('{:.0%}'.format(step[names]/step_group_total).replace('%',''))
                if Groups_Count[names]==0:
                    continue
        except ZeroDivisionError:
            pass
    return Groups_Count
    



def total_rate(Count_data):
    Total_Groups_Count={}
    group_list_path=os.listdir('../Malware_Sample')
    for group in group_list_path:
        Total_Groups_Count[group]=0
    ####################################################################
    hash_matching_result=Count_data['hash_matching_result']
    for Group_0_1 in hash_matching_result:
        if hash_matching_result[Group_0_1]==0:
            continue
        Total_Groups_Count[Group_0_1]=int(Total_Groups_Count[Group_0_1]+(hash_matching_result[Group_0_1]*100/100))
    ####################################################################
    ssdeep_hash_match_result=Count_data['ssdeep_hash_match_result']
    for Group_0_2 in ssdeep_hash_match_result:
        if ssdeep_hash_match_result[Group_0_2]==0:
            continue
        Total_Groups_Count[Group_0_2]=int(Total_Groups_Count[Group_0_2]+(ssdeep_hash_match_result[Group_0_2]*80/100))
    ####################################################################
    repre_func_result=Count_data['Function_Representative_value']
    for Group1 in repre_func_result:
        if repre_func_result[Group1]==0:
            continue
        Total_Groups_Count[Group1]=int(Total_Groups_Count[Group1]+(repre_func_result[Group1]*30/100))

    ####################################################################
    b_b_ssdeep_match_result=Count_data['BB_ssdeep_match_result']
    for Group2 in b_b_ssdeep_match_result:
        if b_b_ssdeep_match_result[Group2]==0:
            continue
        Total_Groups_Count[Group2]=int(Total_Groups_Count[Group2]+(b_b_ssdeep_match_result[Group2]*30/100))
    ####################################################################
    b_b_ssdeep_compare_result=Count_data['BB_ssdeep_compare_result']
    for Group3 in b_b_ssdeep_compare_result:
        if b_b_ssdeep_compare_result[Group3]==0:
            continue
        Total_Groups_Count[Group3]=int(Total_Groups_Count[Group3]+(b_b_ssdeep_compare_result[Group3]*20/100))
    ####################################################################
    Group_Count_4=Count_data['RH_result']
    if Group_Count_4!=None:
        for Group4 in Group_Count_4:
            if Group_Count_4[Group4]==0:
                continue
            else:
                Total_Groups_Count[Group4]=int(Total_Groups_Count[Group4]+42)
    ####################################################################            
    b_b_ngram_score_result=Count_data['BB_ngram_compare_result']
    for Group5 in b_b_ngram_score_result:
        if b_b_ngram_score_result[Group5]==0:
            continue
        Total_Groups_Count[Group5]=int(Total_Groups_Count[Group5]+(b_b_ngram_score_result[Group5]*30/100))

    ####################################################################    
    constant_value_score_result=Count_data['constant_value_score']
    for Group6 in constant_value_score_result:
        if constant_value_score_result[Group6]==0:
            continue
        Total_Groups_Count[Group6]=int(Total_Groups_Count[Group6]+(constant_value_score_result[Group6]*23/100))
            
    ####################################################################       
    peinfo_score_result=Count_data['peinfos']
    for Group7 in peinfo_score_result:
        if peinfo_score_result[Group7]==0:
            continue
        Total_Groups_Count[Group7]=int(Total_Groups_Count[Group7]+(peinfo_score_result[Group7]*40/100))     

    ####################################################################
    distance_score_result=Count_data['distance']
    for Group8 in distance_score_result:
        if distance_score_result[Group8]==0:
            continue
        Total_Groups_Count[Group8]=int(Total_Groups_Count[Group8]+(distance_score_result[Group8]*23/100))  
    ####################################################################
    strings_score_result=Count_data['strings']
    for Group9 in strings_score_result:
        if strings_score_result[Group9]==0:
            continue
        Total_Groups_Count[Group9]=int(Total_Groups_Count[Group9]+(strings_score_result[Group9]*52/100))  
            
    return Total_Groups_Count

########################################################################################################



########################################################################################################
def Call_Step(queue):
    while True:
        if queue.empty()!=True:
            time.sleep(15)
            continue

        json_file=queue.get()
        print(json_file)



        json_file_read=open(json_file,encoding='utf-8').read()
        json_data=json.loads(json_file_read)
        
        
        strings_Queue=Queue()
        strings_Thread = Process(target=step9_strings_score, args=(json_data,strings_Queue,))
        strings_Thread.start()


        
        start_time=time.time()
        sims=Sim_rate(json_file)
        end_time=time.time()
        e=int(end_time-start_time)
        print('{:02d}:{:02d}:{:02d}'.format(e // 3600, (e % 3600 // 60), e % 60))
        ###############FAILS############################
        if sims.flag==1:
            try:
                os.remove(json_file)
                os.remove(glob.glob(os.path.join('/home/bob/IDB_TMP/User_Sample/idb_samples',json_data['pe_random'])+'*')[0])
                mutex_queue.remove(json_file)
            except:
                pass
        
            try:
                mutex_queue.remove(json_file)
                strings_Queue.get()
                
            except:
                pass
            continue
        
        
        ####################################################################
        start_time=time.time()
        file_hash_match_dic,file_hash_match_sum=sims.step_file_hash_matching()#딕셔널리, 개수
        hash_matching_result=Print_Rate(file_hash_match_dic,file_hash_match_sum,flag=1)
        print('\tstep1 Hash Match Ok')
        end_time=time.time()
        e=int(end_time-start_time)
        print('{:02d}:{:02d}:{:02d}'.format(e // 3600, (e % 3600 // 60), e % 60))
        ####################################################################
        start_time=time.time()
        ssdeep_hash_match_dic,ssdeep_hash_match_sum=sims.step0_file_ssdeep_hash_matching()
        ssdeep_hash_match_result=Print_Rate(ssdeep_hash_match_dic,ssdeep_hash_match_sum,flag=1)
        print('\tstep2 SSDEEP Match Ok')
        end_time=time.time()
        e=int(end_time-start_time)
        print('{:02d}:{:02d}:{:02d}'.format(e // 3600, (e % 3600 // 60), e % 60))
        ####################################################################
        start_time=time.time()
        repre_func_dic,repre_func_sum, mutex_opcode_list=sims.step1_repre_func()
        repre_func_result=Print_Rate(repre_func_dic,repre_func_sum,flag=0)
        print('\tstep3 func repre Ok')
        end_time=time.time()
        e=int(end_time-start_time)
        print('{:02d}:{:02d}:{:02d}'.format(e // 3600, (e % 3600 // 60), e % 60))
        ####################################################################
        start_time=time.time()
        b_b_ssdeep_match_dic,b_b_ssdeep_match_sum=sims.step2_ssdeep_matching()
        b_b_ssdeep_match_result=Print_Rate(b_b_ssdeep_match_dic,b_b_ssdeep_match_sum,flag=0)
        print('\tstep4 bb ssdeep Ok')
        end_time=time.time()
        e=int(end_time-start_time)
        print('{:02d}:{:02d}:{:02d}'.format(e // 3600, (e % 3600 // 60), e % 60))
        ####################################################################
        start_time=time.time()
        b_b_ssdeep_compare_dic,b_b_ssdeep_compare_sum=sims.step3_ssdeep_compare(mutex_opcode_list)
        b_b_ssdeep_compare_result=Print_Rate(b_b_ssdeep_compare_dic,b_b_ssdeep_compare_sum,flag=0)
        print('\tstep5 bb compare Ok')
        end_time=time.time()
        e=int(end_time-start_time)
        print('{:02d}:{:02d}:{:02d}'.format(e // 3600, (e % 3600 // 60), e % 60))
        ####################################################################4
        start_time=time.time()
        RH_result=sims.step4_Rich_header()
        print('\tstep6 rich Ok')
        end_time=time.time()
        e=int(end_time-start_time)
        print('{:02d}:{:02d}:{:02d}'.format(e // 3600, (e % 3600 // 60), e % 60))
        ####################################################################
        start_time=time.time()
        b_b_ngram_score_dic,b_b_ngram_score_sum=sims.step5_ngram_score(mutex_opcode_list)
        b_b_ngram_score_result=Print_Rate(b_b_ngram_score_dic,b_b_ngram_score_sum,flag=0)
        print('\tstep7 bb ngram Ok')
        end_time=time.time()
        e=int(end_time-start_time)
        print('{:02d}:{:02d}:{:02d}'.format(e // 3600, (e % 3600 // 60), e % 60))
        ####################################################################
        start_time=time.time()
        constant_value_score_dic,constant_value_score_sum=sims.step6_constant_value_score()
        constant_value_score_result=Print_Rate(constant_value_score_dic,constant_value_score_sum,flag=1)
        print('\tstep8 constant Ok')
        end_time=time.time()
        e=int(end_time-start_time)
        print('{:02d}:{:02d}:{:02d}'.format(e // 3600, (e % 3600 // 60), e % 60))
        ####################################################################
        start_time=time.time()
        peinfo_Groups_Count, peinfo_score_sum=sims.step7_peinfos()
        peinfo_score_result=Print_Rate(peinfo_Groups_Count, peinfo_score_sum,flag=0)
        print('\tstep9 pe infos Ok')
        end_time=time.time()
        e=int(end_time-start_time)
        print('{:02d}:{:02d}:{:02d}'.format(e // 3600, (e % 3600 // 60), e % 60))
        ####################################################################
        start_time=time.time()
        calling_dsitance_Groups_Count,distance_value_score_sum=sims.step8_calling_distance()
        distance_score_result=Print_Rate(calling_dsitance_Groups_Count,distance_value_score_sum,flag=1)
        print('\tstep10 calling distance Ok')
        end_time=time.time()
        e=int(end_time-start_time)
        print('{:02d}:{:02d}:{:02d}'.format(e // 3600, (e % 3600 // 60), e % 60))
        ####################################################################

        
        
        ##베이직 블록별 유사도 측정##
        start_time=time.time()
        Opcode_Indexing_result=sims.basic_block_index_infos()
        idb_basicblock_matched=sims.Opcode_Indexing_conduct(Opcode_Indexing_result)    
        print('\tBasicBlock ends Ok')
        end_time=time.time()
        e=int(end_time-start_time)
        print('{:02d}:{:02d}:{:02d}'.format(e // 3600, (e % 3600 // 60), e % 60))
        ####################################################################
        
        start_time=time.time()
        strings_Thread.join()
        step9_Groups_Count,b_b_ngram_score_sum=strings_Queue.get()
        strings_matched=Print_Rate(step9_Groups_Count,b_b_ngram_score_sum,flag=0)
        #step9_Groups_Count,b_b_ngram_score_sum=sims.step9_strings_score()
        print('\tstep11 strings ends Ok')
        end_time=time.time()
        e=int(end_time-start_time)
        print('{:02d}:{:02d}:{:02d}'.format(e // 3600, (e % 3600 // 60), e % 60))
        ####################################################################
        
        Count_data={
            'hash_matching_result':hash_matching_result,
            'ssdeep_hash_match_result':ssdeep_hash_match_result,
    
            'Function_Representative_value':repre_func_result,
            'BB_ssdeep_match_result':b_b_ssdeep_match_result,
            'BB_ssdeep_compare_result':b_b_ssdeep_compare_result,
    
            'RH_result':RH_result,
    
            'BB_ngram_compare_result':b_b_ngram_score_result,
            'constant_value_score':constant_value_score_result,
            'peinfos':peinfo_score_result,
            'distance':distance_score_result,
            'strings':strings_matched
        }
        Total_Groups_Count=total_rate(Count_data)
        ############################################################    
    
        json_file_read=open(json_file,encoding='utf-8').read()
        json_data=json.loads(json_file_read)
    
    
        idb_total_matched={}
        idb_original_matched={}
        
        group_list_path=os.listdir('../Malware_Sample')

        #count_data_dict={}
        #for group in group_list_path:
        #    count_data_dict[group]
        pe_total_groups=[]
        result_for_clustering = True
        for group in group_list_path:
            sims_dict={}
            #파일에 대한 전체 유사도를 검증한 결과값이다. 50점 이상이면 그룹명을 지정해준다.
            sims_dict['totals']=Total_Groups_Count[group]
            idb_original_dict={}

            ######특정 점수  이상 시 자동으로 SEED DB 저장###### 
            if sims_dict['totals']>160:
                if group=="GandCrab":
                    if sims_dict['totals']>200:
                        result_for_clustering = False
                        #70점 이상일 시 group이 담겨진다. 일종의 플래그
                        pe_total_groups.append(group)
                        json_data['pe_groups']=pe_total_groups
                else:
                    result_for_clustering = False
                    #70점 이상일 시 group이 담겨진다. 일종의 플래그
                    pe_total_groups.append(group)
                    json_data['pe_groups']=pe_total_groups


            elif sims_dict['totals']>78:
                json_data['pe_groups']=pe_total_groups
                
                
            #각 유사도에 대한 그룹별 수치를 담아낸다.
            sims_dict['hash_matching_result']=Count_data['hash_matching_result'][group]
            sims_dict['ssdeep_hash_match_result']=Count_data['ssdeep_hash_match_result'][group]
            sims_dict['Function_Representative_value']=Count_data['Function_Representative_value'][group]
            sims_dict['BB_ssdeep_match_result']=Count_data['BB_ssdeep_match_result'][group]
            sims_dict['BB_ssdeep_compare_result']=Count_data['BB_ssdeep_compare_result'][group]
            #RH_result : rich_header이므로 None 값이 나올 수 있다.
            try:
                sims_dict['RH_result']=Count_data['RH_result'][group]
            except:
                sims_dict['RH_result']="None"
            sims_dict['BB_ngram_compare_result']=Count_data['BB_ngram_compare_result'][group]
            sims_dict['constant_value_score']=Count_data['constant_value_score'][group]
            sims_dict['peinfo_score_result']=Count_data['peinfos'][group]
            sims_dict['distance_score_result']=Count_data['distance'][group]
            sims_dict['strings_score_result']=Count_data['strings'][group]
            
            idb_original_dict['hash_matching_result']=hash_matching_result[group]
            idb_original_dict['ssdeep_hash_match_result']=ssdeep_hash_match_result[group]
            idb_original_dict['Function_Representative_value']=repre_func_result[group]
            idb_original_dict['BB_ssdeep_match_result']=b_b_ssdeep_match_result[group]
            idb_original_dict['BB_ssdeep_compare_result']=b_b_ssdeep_compare_result[group]
            try:
                idb_original_dict['RH_result']=RH_result[group]
            except:
                idb_original_dict['RH_result']="None"
            idb_original_dict['BB_ngram_compare_result']=b_b_ngram_score_result[group]
            idb_original_dict['constant_value_score']=constant_value_score_result[group]
            idb_original_dict['peinfo_score_result']=peinfo_score_result[group]
            idb_original_dict['distance_score_result']=distance_score_result[group]
            idb_original_dict['strings_score_result']=strings_matched[group]
                    
            try:
                idb_total_matched[group]=sims_dict
                idb_original_matched[group]=idb_original_dict
            except:
                continue
                

            
            
        #if(result_for_clustering == True):
        cl.clustering().metadata_parsing()
        json_data['idb_total_matched']=idb_total_matched
        json_data['idb_basicblock_matched']=idb_basicblock_matched
        json_data['idb_total_matched_original']=idb_original_matched
        
        
        ########백업 생성###########################################
        dt = datetime.now()
        json_file_name='{}_{}_{}_{}_{}_{}'.format(dt.year,dt.month,dt.day,dt.hour,dt.minute,dt.microsecond)
        
        
        if json_data['pe_groups']!=None and json_data['pe_groups']!=[]:
            groups_join='_'.join(json_data['pe_groups'])
            json_file_full_path=os.path.join('/home/bob/IDB_TMP/BackUp/json_backup',groups_join+'_'+json_file_name+'.json')
            with open(json_file_full_path, 'w', encoding="utf-8") as make_file:
                json.dump(json_data, make_file, ensure_ascii=False, indent="\t")
        else:
            json_file_full_path=os.path.join('/home/bob/IDB_TMP/BackUp/json_backup',"None"+'_'+json_file_name+'.json')
            with open(json_file_full_path, 'w', encoding="utf-8") as make_file:
                json.dump(json_data, make_file, ensure_ascii=False, indent="\t")
        ############################################################
        
        
        ############################################################
        m2push = M2push.M2push(url="https://m2lab.io", username="MASTER_ADMIN",api_key="900BB2D2300A947B90AB55B80D74A05376828EEEC816510CF2F1526AEEACCD6A")
        if m2push.send(json_data, type='linux') is False:
            print("Fail.")
        ############################################################        
        
        ############################################################
        ##클러스터링 수정바람##
        
        #위에서 70점 이상인 group 인 것이 있었으면 insert를 진행한다.
        if len(pe_total_groups)>0:
            #for groups in pe_total_groups:
            basic_block_result_list, constant_result_list, distance_result_list, FUNCTION_REPRE_INSERT_LIST=sims.Sim_rate_infos()
            #print(basic_block_result_list, constant_result_list, distance_result_list, FUNCTION_REPRE_INSERT_LIST)
            M_insert=insert_db_pass_web.main_insert(json_data)
            M_insert.ssdeep_db_insert()
            M_insert.DATABASE_INSERT(FUNCTION_REPRE_INSERT_LIST)
            M_insert.constant_value(constant_result_list)
            M_insert.RH_insert()
            M_insert.Distance(distance_result_list)
            M_insert.peinfo()
            print("DB Insert Clustering")
        
        ############################################################      
        print("\tEnds")
        

        try:
            os.remove(json_file)
            os.remove(glob.glob(os.path.join('/home/bob/IDB_TMP/User_Sample/idb_samples',json_data['pe_random'])+'*')[0])
            mutex_queue.remove(json_file)
        except:
            pass
        
mutex_queue=[]
class queue_create:
    def __init__(self,queue):
        self.json_folder_full_path='/home/bob/IDB_TMP/User_Sample/json_samples'
        self.queue=queue
    
    
    def queue_put(self):
        while True:
            for json_file in os.listdir(self.json_folder_full_path):
                if json_file in mutex_queue:
                    continue
                self.queue.put(os.path.join(self.json_folder_full_path,json_file))
                mutex_queue.append(json_file)
            
            time.sleep(5)
    '''
    def queue_put(self):
        for json_file in os.listdir(self.json_folder_full_path):
            self.queue.put(os.path.join(self.json_folder_full_path,json_file))
    '''     
if __name__=="__main__":
    queue=Queue()
    Mains=queue_create(queue)
    threads_queue = threading.Thread(target=Mains.queue_put, args=())
    #threads_queue.daemon = True 
    threads_queue.start()
    
   
   
    #가동할 프로세스 숫자
    numprocess=20
    #Call_Step(queue)
    
    
    while True:
        proc_list=[]
        for _ in range(0,numprocess):
            proc=Process(target=Call_Step,args=(queue,))
            proc_list.append(proc)
    
        for proc in proc_list:
            proc.start()
        
        for proc in proc_list:
            proc.join()
