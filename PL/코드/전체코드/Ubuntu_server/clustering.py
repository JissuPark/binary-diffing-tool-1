# Hash : 이전 코드에서 필터링을 했기에 불필요 
# ssdeep_file : compare을 이용하여 시도 
# rh_info : True/False 
# Func_repre : True/False 
# bb_ssdeep : compare
# constant_value : true/false [수정 필요]
# opcode_info : ngram

import Elastic
import ElasticQueryMaster
import operator as op
import Elastic_for_clustering as efc


def file_data_extraction(file_all_info):
    file_info ={}
    basicblock_info = {}
    b_b_ssdeep = []
    b_b_func_repre = [] 
    b_b_number = []
    b_b_opcod_info = [] 
    
    # 해시가 바뀜
    for i in range(0,file_all_info['total']):
        file_info['sha256'] = file_all_info['hits'][i]['_source']['sha256']
        file_info['ssdeep'] = file_all_info['hits'][i]['_source']['ssdeep']
        file_info['rh_info'] = file_all_info['hits'][i]['_source']['rh_info']
        file_info['constant_value'] = file_all_info['hits'][i]['_source']['constant_value']
        
        #bb가 바뀜
        basicblock_info['sha256'] = file_info['sha256']
        
        basicblock_all_info=efc.get_basicblock_info(file_info['sha256'])
        for i in range(0,basicblock_all_info['total']):
            try:
                b_b_func_repre.append(basicblock_all_info['hits'][i]['_source']['func_repre'])
            except:
                b_b_func_repre.append('')
            b_b_number.append(basicblock_all_info['hits'][i]['_source']['bb_number']) 
            b_b_ssdeep.append(basicblock_all_info['hits'][i]['_source']['ssdeep'])
            b_b_opcod_info.append(basicblock_all_info['hits'][i]['_source']['opicode_info'])
        
        basicblock_info['bb_number'] = b_b_number
        basicblock_info['ssdeep'] = b_b_ssdeep
        basicblock_info['func_repre'] = b_b_func_repre
        basicblock_info['opcode_info'] = b_b_opcod_info

        return file_info, basicblock_info

def Print_Rate(match_dic,match_sum,flag):
    Groups_Count={}
    for group in match_dic:
        Groups_Count[group]=0
    if flag==0:
        if match_sum>=1:
            try:
                for names in match_dic:
                    Groups_Count[names]=int('{:.0%}'.format(match_dic[names]/match_sum).replace('%',''))
                    if Groups_Count[names]==0:
                        continue
            except ZeroDivisionError:
                pass

    elif flag==1:
        try:
            for names in match_dic:
                Groups_Count[names]=int('{:.0%}'.format(match_dic[names]/match_sum).replace('%',''))
                if Groups_Count[names]==0:
                    continue
        except ZeroDivisionError:
            pass
    return Groups_Count   
    
    
def simiarity_Measure(file_info,basicblock_info):
    #{해시 : 카운트 값}
    #################################################################################################################################################
    file_hash_match_dic,file_hash_match_sum = efc.ssdeep_match_for_clustering(file_info['ssdeep'], 50,file_info['sha256'])
    ssdeep_hash_match_result=Print_Rate(file_hash_match_dic,file_hash_match_sum,1)
    #################################################################################################################################################
    RH_result = efc.RH_matching_for_clustering(file_info['rh_info'],file_info['sha256']) # RH 매칭
    #################################################################################################################################################
    b_b_ssdeep_match_dic,b_b_ssdeep_match_sum=efc.ssdeep_matching_for_clustering(basicblock_info['ssdeep'],file_info['sha256'])
    b_b_ssdeep_match_result=Print_Rate(b_b_ssdeep_match_dic,b_b_ssdeep_match_sum,0)
    #################################################################################################################################################
    ssdeep_hash_match_dic,ssdeep_hash_match_sum = efc.ssdeep_compare_for_clustering(basicblock_info['ssdeep'],file_info['sha256'])
    b_b_ssdeep_compare_result=Print_Rate(ssdeep_hash_match_dic,ssdeep_hash_match_sum,0)
    #################################################################################################################################################
    func_repre_dic,func_repre_sum=efc.func_repre_block_for_clustering(basicblock_info['func_repre'],file_info['sha256'])
    repre_func_result=Print_Rate(func_repre_dic,func_repre_sum,0)
    #################################################################################################################################################
    b_b_ngram_score_dic,b_b_ngram_score_sum=efc.find_opcode_nagram_for_clustering(basicblock_info['opcode_info'],file_info['sha256'])
    b_b_ngram_score_result=Print_Rate(b_b_ngram_score_dic,b_b_ngram_score_sum,0)
    #################################################################################################################################################
    #constant_Value_Score [미 완성]
    #basic_blick_info [수정 필요하다고함]
    
    
    
    Count_data={
        #'hash_matching_result':hash_matching_result,
        'ssdeep_hash_match_result':ssdeep_hash_match_result,
        'Function_Representative_value':repre_func_result,
        'BB_ssdeep_match_result':b_b_ssdeep_match_result,
        'BB_ssdeep_compare_result':b_b_ssdeep_compare_result,
        'RH_result':RH_result,
        'BB_ngram_compare_result':b_b_ngram_score_result,
    }

    Total_Groups_Count=total_rate(Count_data)
    
    
    
    
def total_rate(Count_data):
    Total_Groups_Count={}
    
    for Group1 in Count_data['ssdeep_hash_match_result']:
        Total_Groups_Count[Group1]=0
    for Group2 in Count_data['Function_Representative_value']:
        Total_Groups_Count[Group2]=0
    for Group3 in Count_data['BB_ssdeep_match_result']:
        Total_Groups_Count[Group3]=0
    for Group4 in Count_data['BB_ssdeep_compare_result']:
        Total_Groups_Count[Group4]=0
    for Group5 in Count_data['RH_result']:
        Total_Groups_Count[Group5]=0
    for Group6 in Count_data['BB_ngram_compare_result']:
        Total_Groups_Count[Group6]=0
    
    
    ssdeep_hash_match_result=Count_data['ssdeep_hash_match_result']
    for Group_0_2 in ssdeep_hash_match_result:
        if ssdeep_hash_match_result[Group_0_2]==0:
            continue
        Total_Groups_Count[Group_0_2]=int(Total_Groups_Count[Group_0_2]+(ssdeep_hash_match_result[Group_0_2]*80/100))
    
    repre_func_result=Count_data['Function_Representative_value']
    for Group1 in repre_func_result:
        if repre_func_result[Group1]==0:
            continue
        Total_Groups_Count[Group1]=int(Total_Groups_Count[Group1]+(repre_func_result[Group1]*30/100))


    b_b_ssdeep_match_result=Count_data['BB_ssdeep_match_result']
    for Group2 in b_b_ssdeep_match_result:
        if b_b_ssdeep_match_result[Group2]==0:
            continue
        Total_Groups_Count[Group2]=int(Total_Groups_Count[Group2]+(b_b_ssdeep_match_result[Group2]*30/100))

    b_b_ssdeep_compare_result=Count_data['BB_ssdeep_compare_result']
    for Group3 in b_b_ssdeep_compare_result:
        if b_b_ssdeep_compare_result[Group3]==0:
            continue
        Total_Groups_Count[Group3]=int(Total_Groups_Count[Group3]+(b_b_ssdeep_compare_result[Group3]*10/100))
    
    Group_Count_4=Count_data['RH_result']
    if Group_Count_4!=None:
        for Group4 in Group_Count_4:
            if Group_Count_4[Group4]==0:
                continue
            else:
                Total_Groups_Count[Group4]=int(Total_Groups_Count[Group4]+5)
                
    b_b_ngram_score_result=Count_data['BB_ngram_compare_result']
    for Group5 in b_b_ngram_score_result:
        if b_b_ngram_score_result[Group5]==0:
            continue
        Total_Groups_Count[Group5]=int(Total_Groups_Count[Group5]+(b_b_ngram_score_result[Group5]*30/100))

            
    return Total_Groups_Count

if __name__=="__main__": 
    file_info, basicblock_info=file_data_extraction(efc.get_file_info())
    simiarity_Measure(file_info, basicblock_info)


    
    