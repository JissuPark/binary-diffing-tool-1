import hashlib
from collections import OrderedDict
import ssdeep
from ngram import NGram
import operator
import numpy as np
import json

'''
                pe_t['imphash'] = res_imphash
                pe_t['implist'] = res_implist
                pe_t['rich'] = res_rich
                pe_t['section_score'] = res_sec
                pe_t['cert_score'] = res_cert
                pe_t['pdb_score'] = res_pdb
                pe_t['rsrc'] = res_rsrc
'''

def Calc_All(pe_t):
    #모든 요소가 있는 경우
    score = 0
    score += pe_t['imphash']
    score += pe_t['rich']
    score += pe_t['section_score']
    score += pe_t['cert_score']
    score += pe_t['pdb_score']
    score += pe_t['rsrc']

    score = score / 6
    score = round(score, 2)
    print(f"score for all :: {score}")
    return score

def Calc_Without_Pdb(pe_t):
    score = 0
    if np.isnan(pe_t['rsrc']):
        #pdb와 rsrc가 없는 경우
        score += Calc_Without_Pdb_and_Rsrc(pe_t)
    elif np.isnan(pe_t['cert_score']):
        score += Calc_Without_Pdb_and_Cert(pe_t)
    else:
        #pdb만 없는 경우 가중치 부여
        score += pe_t['imphash']
        score += pe_t['rich']
        score += pe_t['section_score']
        score += pe_t['cert_score']
        score += pe_t['rsrc']

        score = score / 5
        score = round(score, 2)
        print(f"score without pdb :: {score}")
    return score

def Calc_Without_Pdb_and_Rsrc(pe_t):
    score = 0
    if np.isnan(pe_t['cert_score']):
        #pdb, rsrc, cert 모두 없는 경우
        score += Calc_Without_All(pe_t)
    else:
        #pdb, rsrc 없는 경우의 가중치 부여
        score += pe_t['imphash']
        score += pe_t['rich']
        score += pe_t['section_score']
        score += pe_t['cert_score']

        score = score / 4
        score = round(score, 2)
        print(f"score without pdb and rsrc :: {score}")
    return score

def Calc_Without_Pdb_and_Cert(pe_t):
    score = 0
    #pdb, cert가 없는 경우
    score += pe_t['imphash']
    score += pe_t['rich']
    score += pe_t['section_score']
    score += pe_t['rsrc']

    score = score / 4
    score = round(score, 2)
    print(f"score without pdb and cert :: {score}")
    return score

def Calc_Without_All(pe_t):
    score = 0

    score += pe_t['imphash']
    score += pe_t['rich']
    score += pe_t['section_score']

    score = score / 3
    score = round(score, 2)
    print(f"score without pdb, rsrc and cert :: {score}")

    return score

def Calc_Without_Rsrc(pe_t):
    score = 0
    if np.isnan(pe_t['cert_score']):
        #rsrc와 cert가 없는 경우
        score += Calc_Without_Rsrc_and_Cert(pe_t)
    else:
        #rsrc만 없는 경우 가중치 부여

        score += pe_t['imphash']
        score += pe_t['rich']
        score += pe_t['section_score']
        score += pe_t['cert_score']
        score += pe_t['pdb_score']

        score = score / 5
        score = round(score, 2)
        print(f"score without rsrc :: {score}")
    return score

def Calc_Without_Rsrc_and_Cert(pe_t):
    score = 0

    score += pe_t['imphash']
    score += pe_t['rich']
    score += pe_t['section_score']
    score += pe_t['pdb_score']

    score = score / 4
    score = round(score, 2)
    print(f"score without rsrc and cert :: {score}")

    return score

def Calc_Without_Cert(pe_t):
    #cert만 없는 경우
    score = 0

    score += pe_t['imphash']
    score += pe_t['rich']
    score += pe_t['section_score']
    score += pe_t['pdb_score']
    score += pe_t['rsrc']

    score = score / 5
    score = round(score, 2)
    print(f"score without cert :: {score}")

    return score



class AnalyzePE:
    def __init__(self, pe_all):
        self.pe_all = pe_all
        '''
        PE data를 받아오면 변수로 저장해주는 생성자 
        :param: S_PE : data piece about PE of stand data from input 
        :param: T_PE : data piece about PE of stand data from input 
        '''

    def pe_parser(self):
        '''
        PE data가 들어오면 rsrc, rich, pdb로 파싱해서 각 함수에서 사용할 수 있게 해주는 함수
        *파싱만 잘해서 넘겨주면 각 함수는 크게 할 일이 없고 cmp함수 호출해서 나오는 결과에 따라 가중치만 부여해주면 됨
        :return: none
        '''
        pe_list = list()

        pe_all_dict = sorted(self.pe_all.items(), key=operator.itemgetter(0))
        for f_name, f_info in pe_all_dict:
            pe_list.append(f_info)
        return pe_list

    def analyze_imphash(self, standard, target):
        '''
        PE에서 imphash를 뽑아서 비교해 참/거짓에 따라 점수를 반환하는 함수
        *hash 값 하나짜리라 cmp_hash를 쓸 필요가 없음
        :return: score with weight
        '''

        # for var in standard.values():
        #     if var == 'imp_hash':
        #         s = var

        if standard['imp_hash'] == target['imp_hash']:
            return 100
        else:
            return 0

    def analyze_implist(self, standard, target):
        '''
        imp list에서 두 바이너리가 공동으로 사용하는 dll과 내부의 함수를 보여줄 생각
        :return :: import dll list, 점수로도 치환하는 것이 좋을까?
        '''
        same_dict = dict()
        Fsize = 0
        score = 0
        for k in standard.keys():
            Fsize += len(standard[k])
        if standard != {} and target != {}:
            for key1 in standard.keys():
                for key2 in target.keys():
                    if key1 == key2:
                        for i in standard[key1]:
                            if i in target[key2]:
                                same_dict[key1] = i
                                score += 1
                            else:
                                continue
                    else:
                        continue
            #print(f"implist score :: {score}")
            #print(f"implist Fsize :: {Fsize}")
            return round(score / Fsize * 100, 2)
        else:
            return 0

        #print(same_dict)
        # 두 바이너리에서 공통으로 사용하는 dll과 내부의 함수들을 딕셔너리 형태로 리턴
        return same_dict

    def analyze_auth(self, dict_s, dict_t):
        '''
        인증서의 data 자체를 ssdeep으로 비교해서 얼마나 같은지 계산해 반환하는 함수
        :return: score with weight
        '''
        if dict_s.get('hash') == None or dict_t.get('hash') == None:
            return np.nan
        else:
            if dict_s['hash'] == dict_t['hash']:
                score = 100
                return score
            else:
                score = 0
                return score
        return round(score, 2)

    def analyze_pdb(self, dict_s, dict_t):
        '''
        pdb의 GUID는 hash로 비교(ToF)
        pdb의 pdb path는 ngram으로 비교(유사도 수치)
        가중치는 0.5씩
        :return:
        '''
        guid_score = 0
        path_score = 0
        if dict_s['pe_pdb_GUID'] == "" or dict_t['pe_pdb_GUID'] == "":
            return np.nan
        else:
            s_guid = hashlib.md5(dict_s['pe_pdb_GUID'].encode()).hexdigest()
            t_guid = hashlib.md5(dict_t['pe_pdb_GUID'].encode()).hexdigest()
            if s_guid == t_guid:
                guid_score += 50
            else:
                guid_score += 0
        if dict_s['pe_pdb_Pdbpath'] == "" or dict_t['pe_pdb_Pdbpath'] == "":
            path_score += 0
        else:
            path_score += NGram.compare(dict_s['pe_pdb_Pdbpath'], dict_t['pe_pdb_Pdbpath'], N=2) * 50

        score = (guid_score + path_score)
        #score = str(guid_score)+','+str(path_score)     #하나로 묶어야 함

        return round(score, 2)

    def analyze_rsrc(self, standard, target):
        '''
        리소스 데이터를 각각 ssdeep으로 비교해서 결과를 반환하는 함수
        :return: score list with weight
        '''
        if standard != {} and target != {}:
            size = len(standard.keys())
            print(f"size of rsrc :: {size}")
            flag = 0
            for key in standard.keys() and target.keys():
                if key in standard and key in target:
                    if standard[key]['Resource Type'] == target[key]['Resource Type']:
                        if standard[key]['Resource Type'] == 'UNKNOWN' and target[key]['Resource Type'] == 'UNKNOWN':
                            return ssdeep.compare(standard[key]['ssdeep'], target[key]['ssdeep'])
                        else:
                            if standard[key]['sha-256'] == target[key]['sha-256']:
                                flag += 1
                            else:
                                continue
        else:
            return np.nan

        '''
        리소스에 쉘코드가 삽입되어 있는 경우
        어느 리소스에 쉘코드가 들어있는지 모르고
        몇개나 매칭되는지 모르기 때문에
        좀 다른 방식으로 return 값을 정해줘야 할 것 같다. -> 여러 개에서 유사도 수치가 나올 수 있으므로
        standard 리소스 1, 2, 3, 4, 5
        target 리소스 1, 2, 3
        이렇게 있을 경우
        standard 1번과 target에 2번의 유사도 수치가 나온다고 치면
        return : standard 1, target 2, (유사도 수치) 이런식으로?
        '''
        score = 0
        if flag > 0:
            return round(flag / size * 100, 2)
        else:
            return round(score, 2)

    def analyze_rich(self, standard, target):
        '''
        리치 헤더 데이터의 comid, count, prodid를 비교하는 함수
        *문자열로 뽑아서 한다면 ngram을, 데이터 자체를 뽑아서 한다며 data를 사용.. 재호랑 얘기해서하기
        :return: score with weight
        '''
        xor_score = 0
        prodid_score = 0
        if standard['rich_xor_key'] == "" or target['rich_xor_key'] == "":
            return np.nan
        else:
            #rich header의 xor key 유사도(True or False)
            if standard['rich_xor_key'] == target['rich_xor_key']:
                xor_score += 50
            else:
                xor_score += 0

            for prod in standard['rich_prodid']:
                if prod in target['rich_prodid']:
                    #print(f"prod :: {prod}")
                    prodid_score += 1
                else:
                    continue

        #print(f"prodid_score :: {prodid_score}")
        #print(f"len(standard['rich_prodid'] :: {len(standard['rich_prodid'])}")
        prodid_score = prodid_score / len(standard['rich_prodid']) * 50
        score = xor_score + prodid_score

        return round(score, 2)

    def analyze_section(self, dict_s, dict_t):
        '''
        section 별 정보를
        *값이 다 작은 거라서 비교 알고리즘을 쓰기도 모호하고.. 훈이랑 얘기해봐야 할듯
        :return: score with weight
        '''
        score = 0
        print("dict_s.keys() :: ", dict_s.keys())
        for key in dict_s.keys() and dict_t.keys():                                 #키의 이름이 다를 때의 예외처리가 필요
            if key in dict_s and key in dict_t:
                if dict_s[key]['section_name'] == dict_t[key]['section_name']:
                    ss = ssdeep.compare(dict_s[key]['hash_ssdeep'], dict_t[key]['hash_ssdeep']) / len(dict_s.keys())
                    score += ss
            else:
                continue
        return round(score, 2)

    def analyze_all(self, pe_list):

        pe_all = OrderedDict()
        yun_me = dict()
        for index_1, pe_info_s in enumerate(pe_list):
            pe_s = OrderedDict()
            for index_2, pe_info_t in enumerate(pe_list):
                pe_t = OrderedDict()
                yun_t = dict()
                if index_1 == index_2:
                    continue

                pe_t['file_hash'] = pe_info_t['file_hash']
                pe_t['time_date_stamp'] = pe_info_t['time_date_stamp']

                ######   연대기 추가  ######

                yun_t['timestamp'] = pe_info_t['time_date_stamp']
                yun_t['timestamp_num'] = pe_info_t['time in num']

                yun_me[pe_info_t['file_name']] = yun_t

                ### 가중치 부여 ###

                res_imphash = self.analyze_imphash(pe_info_s, pe_info_t)
                res_implist = self.analyze_implist(pe_info_s['Imports'], pe_info_t['Imports'])
                res_rich = self.analyze_rich(pe_info_s, pe_info_t)
                res_sec = self.analyze_section(pe_info_s['cmp_section'], pe_info_t['cmp_section'])
                res_cert = self.analyze_auth(pe_info_s['auto'], pe_info_t['auto'])
                res_pdb = self.analyze_pdb(pe_info_s['pdb_info'], pe_info_t['pdb_info'])
                res_rsrc = self.analyze_rsrc(pe_info_s['rsrc_info'], pe_info_t['rsrc_info'])


                #imp hash가 1이 아닐 경우 세세하게 비교
                pe_t['imphash'] = res_imphash
                if pe_t['imphash'] != 100:
                    pe_t['imphash'] = res_implist

                pe_t['rich'] = res_rich
                pe_t['section_score'] = res_sec
                pe_t['cert_score'] = res_cert
                pe_t['pdb_score'] = res_pdb
                pe_t['rsrc'] = res_rsrc

                if np.isnan(pe_t['pdb_score']):
                    all_score = Calc_Without_Pdb(pe_t)
                elif np.isnan(pe_t['rsrc']):
                    all_score = Calc_Without_Rsrc(pe_t)
                elif np.isnan(pe_t['cert_score']):
                    all_score = Calc_Without_Cert(pe_t)
                else:
                    all_score = Calc_All(pe_t)
                pe_t['pe_all_score'] = all_score
                print(f"pe all score :: {all_score}")
                print(f"pe_t :: {json.dumps(pe_t, indent=4)}")

                if np.isnan(pe_t['pdb_score']):
                    pe_t['pdb_score'] = "No Data"
                if np.isnan(pe_t['rsrc']):
                    pe_t['rsrc'] = "No Data"
                if np.isnan(pe_t['cert_score']):
                    pe_t['cert_score'] = "No Data"


                pe_s[pe_info_t['file_name']] = pe_t

            pe_all[pe_info_s['file_name']] = pe_s

        return pe_all




