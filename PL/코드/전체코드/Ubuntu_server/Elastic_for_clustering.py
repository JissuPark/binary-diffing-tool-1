import elasticsearch
import ssdeep
import copy
import json
from time import time
import operator as op

es = elasticsearch.Elasticsearch(['localhost:9200'])

def get_file_info():
    query = {
        "query": {
            "bool": {
                "must": [
                    {"match": {"_type": "record"}}
                ]
            }    
        }
    }
    results = es.search(index='web-fileinfo', body=query)['hits']
    return results


def get_basicblock_info(sha256):
    query = {
        "query": {
            "bool": {
                "must": [
                    {"match": {"file-sha256": sha256}}
                ]
            }    
        }
    }
    results = es.search(index='web-basicblock', body=query)['hits']
    return results



#1단계
#파일 ssdeep 값을 이용한 검색
def ssdeep_match_for_clustering(ssdeep_value, threshold_grade,sha256):
    chunksize, chunk, double_chunk = ssdeep_value.split(':')
    chunksize = int(chunksize)
    step0_Groups_Count={}
    

    query = {
        'query': {
            'bool': {
                'must': [
                    {
                        'terms': {
                            'chunksize': [chunksize, chunksize * 2, int(chunksize / 2)]
                        }
                    },
                    {
                        'bool': {
                            'should': [
                                {
                                    'match': {
                                        'chunk': {
                                            'query': chunk
                                        }
                                    }
                                },
                                {
                                    'match': {
                                        'double_chunk': {
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
    

    results = es.search('web-fileinfo', body=query)

    for record in results['hits']['hits']:
        if(record['_source']['sha256'] != sha256):
            step0_Groups_Count[record['_source']['sha256']]=0

    if len(results['hits']['hits'])>=1:
        if(record['_source']['sha256'] != sha256):
            for record in results['hits']['hits']:
                Groups_Names=record['_source']['sha256']
                step0_Groups_Count[Groups_Names]=op.add(step0_Groups_Count[Groups_Names],1)

    step0_Groups_total=list(step0_Groups_Count.values())
    step0_Groups_total=sum(step0_Groups_total)
    #queue.put(step0_Groups_Count,step0_Groups_total)
    return step0_Groups_Count,step0_Groups_total


def RH_matching_for_clustering(clear_data,sha256):
    step4_Groups_Count={}
    b_b_ssdeep_match_sum = []
    query = {
        "query": {
            "match": {
                "rh_info": clear_data
            }
        }
    }
    results = es.search(index='web-fileinfo', body=query)
        
    for RH_object in results['hits']['hits']:
        if(sha256!=RH_object['_source']['sha256']):
            group = RH_object['_source']['sha256']
            step4_Groups_Count[group]=0
            step4_Groups_Count[group]=op.add(step4_Groups_Count[group],1)
            
    return step4_Groups_Count

def ssdeep_matching_for_clustering(search_value,sha256):
    step2_Groups_Count = {}
    b_b_ssdeep_match_sum = []
    for i in range(0,len(search_value)):
        query = {
          "query": {
            "match": {
              'ssdeep': search_value[i]
            }
          }
        }
        results = es.search('web-basicblock', body=query)
        
        for ssdeep in results['hits']['hits']:
            if(sha256 != ssdeep['_source']['file-sha256']):
                step2_Groups_Count[ssdeep['_source']['file-sha256']] = 0
            
        
        #print(results)
        for BLOCK in results['hits']['hits']:
            if(sha256 != BLOCK['_source']['file-sha256']):
                step2_Groups_Count[BLOCK['_source']['file-sha256']]=op.add(step2_Groups_Count[BLOCK['_source']['file-sha256']],1)

    b_b_ssdeep_match_sum=list(step2_Groups_Count.values())
    b_b_ssdeep_match_sum=sum(b_b_ssdeep_match_sum)
    return step2_Groups_Count,b_b_ssdeep_match_sum

def find_basic_block_by_ssdeep(ssdeep_value,threshold_grade):
    chunksize, chunk, double_chunk = ssdeep_value.split(':')
    chunksize = int(chunksize)
    step2_Groups_Count={}

    query = {
        'query': {
            'bool': {
                'must': [
                    {
                        'terms': {
                            'chunksize': [chunksize, chunksize * 2, int(chunksize / 2)]
                        }
                    },
                    {
                        'bool': {
                            'should': [
                                {
                                    'match': {
                                        'chunk': {
                                            'query': chunk
                                        }
                                    }
                                },
                                {
                                    'match': {
                                        'double_chunk': {
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
    

    results = es.search('web-basicblock', body=query)

    data_to_return = []
    
    for record in results['hits']['hits']:
        record_ssdeep = record['_source']['ssdeep']
        ssdeep_grade = ssdeep.compare(record_ssdeep, ssdeep_value)
        #print(ssdeep_grade)
        
        record['_source']['ssdeep_grade'] = ssdeep_grade

        if ssdeep_grade >= 2:
            data_to_return.append(record['_source'])
        del(record)
    return data_to_return


def ssdeep_compare_for_clustering(ssdeep_value,sha256):
    step3_Groups_Count={}
    for bb_ssdeep in ssdeep_value:
        compare_score=ssdeep.compare(bb_ssdeep,bb_ssdeep)
        BASIC_BLOCK_SSDEEP_MATCHING_ITEMS = find_basic_block_by_ssdeep(bb_ssdeep,45)
        for compare_ssdeep in BASIC_BLOCK_SSDEEP_MATCHING_ITEMS:
            if(compare_ssdeep['file-sha256']!=sha256):
                Groups_Names=compare_ssdeep['file-sha256']
                step3_Groups_Count[Groups_Names] = 0 
        for compare_ssdeep in BASIC_BLOCK_SSDEEP_MATCHING_ITEMS:
            if(compare_ssdeep['file-sha256']!=sha256):
                Groups_Names=compare_ssdeep['file-sha256']
                step3_Groups_Count[Groups_Names]=op.add(step3_Groups_Count[Groups_Names],1)
    
    b_b_ssdeep_compare_sum=list(step3_Groups_Count.values())
    b_b_ssdeep_compare_sum=sum(b_b_ssdeep_compare_sum)
    #queue.put(step3_Groups_Count,b_b_ssdeep_compare_sum)
    return step3_Groups_Count,b_b_ssdeep_compare_sum




def func_repre_block_for_clustering(func_repre,sha256):
    step3_Groups_Count={}
    for each_func_repre in func_repre:
        result_sha256 = find_repre_func_by_ssdeep(each_func_repre,sha256)

    for sha in result_sha256:
        if(sha256 != func_repre['file-sha256']):
            step3_Groups_Count[sha['file-sha256']]=0
        
    for detect_sha in result_sha256:
        if(sha256 != func_repre['file-sha256']):
            Groups_Names=detect_sha['file-sha256']
            step3_Groups_Count[Groups_Names]=op.add(step3_Groups_Count[Groups_Names],1)
    
    repre_func_sum=list(step3_Groups_Count.values())
    repre_func_sum=sum(repre_func_sum)

    return step3_Groups_Count,repre_func_sum
        


        
def search_everything(search_value):
    query = {
      "query": {
        "match": {
          'func_repre': search_value
        }
      }
    }
    results = es.search('web-basicblock', body=query)
    
    return_list = []
    
    for record in results['hits']['hits']:

        return_list.append(
            record['_source']
        )
        
    return return_list
    

def find_repre_func_by_ssdeep(search_value,sha256):
    query = {
      "query": {
        "match": {
          'func_repre': search_value
        }
      }
    }
    results = es.search('web-basicblock', body=query)
    return_list = []
    
    for record in results['hits']['hits']:
        if(record['_source']['file-sha256'] != sha256):
            return_list.append(
                record['_source']
            )
        del(record)
    return return_list

def find_opcode_nagram_for_clustering(opcode_info,sha256):
    step5_Groups_Count={}
    score_totals=0
    score={}
    for bb_opcode_info in opcode_info:
        query = {  
                   "query":{  
                      "match":{  
                         "opicode_info":bb_opcode_info
                      }
                   }
                }
        ngram_search_result_list = es.search(index="web-basicblock", body=query)

        for ngram_search_result_object in ngram_search_result_list['hits']['hits']:
            if(sha256!=ngram_search_result_object['_source']['file-sha256']):
                step5_Groups_Count[ngram_search_result_object['_source']['file-sha256']] = 0
        
        
        if len(ngram_search_result_list)>1:
            for ngram_search_result_object in ngram_search_result_list['hits']['hits']:
                if(sha256!=ngram_search_result_object['_source']['file-sha256']):
                    try:
                        if(score[ngram_search_result_object['_source']['file-sha256']]<ngram_search_result_object['_score']/len(ngram_search_result_object['_source']['opicode_info'])):

                            score[ngram_search_result_object['_source']['file-sha256']]=ngram_search_result_object['_score']/len(ngram_search_result_object['_source']['opicode_info'])
                    except:
                        score[ngram_search_result_object['_source']['file-sha256']]=ngram_search_result_object['_score']/len(ngram_search_result_object['_source']['opicode_info'])
        
        score_sorted=sorted(score.items(),key=op.itemgetter(1),reverse=True) # 나온 값을 Score 별로 소팅 
        for score_object in score_sorted[0:2]:
            score_totals=op.add(score_totals,score_object[1])    # 1등 2등 3등 합치기 
        
        if len(score_sorted)==1:
            num1_max_group_simil=int("{:.0%}".format((score_sorted[0][1]/score_totals)).replace("%",""))
            step5_Groups_Count[score_sorted[0][0]]=op.add(step5_Groups_Count[score_sorted[0][0]],1)
        elif(len(score_sorted)==0):
            step5_Groups_Count = {}
            b_b_ngram_score_sum = 0
            return step5_Groups_Count,b_b_ngram_score_sum
        else:
            num1_max_group_simil=int("{:.0%}".format((score_sorted[0][1]/score_totals)).replace("%",""))
            num2_max_group_simil=int("{:.0%}".format((score_sorted[1][1]/score_totals)).replace("%",""))
            if op.sub(num1_max_group_simil,num2_max_group_simil)>=10:     
                step5_Groups_Count[score_sorted[0][0]]=op.add(step5_Groups_Count[score_sorted[0][0]],1)
         
        b_b_ngram_score_sum=list(step5_Groups_Count.values())
        b_b_ngram_score_sum=sum(b_b_ngram_score_sum)
        #queue.put(step5_Groups_Count,b_b_ngram_score_sum)
        return step5_Groups_Count,b_b_ngram_score_sum    
    


    