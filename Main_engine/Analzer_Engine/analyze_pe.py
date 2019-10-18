import hashlib
from collections import OrderedDict
import ssdeep
from ngram import NGram
import operator
import json
from Main_engine.Analzer_Engine.Algorithm import all_algo as algo


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
        pe_all_dict = OrderedDict()

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
            return 1
        else:
            return 0

    def analyze_auth(self, dict_s, dict_t):
        '''
        인증서의 data 자체를 ssdeep으로 비교해서 얼마나 같은지 계산해 반환하는 함수
        :return: score with weight
        '''
        score = 0
        if dict_s.get('hash') == None or dict_t.get('hash') == None:
            #print("No Authentication")
            return score
        else:
            if dict_s['hash'] == dict_t['hash']:
                score = 1
                return score
            else:
                score = 0
                return score
            '''
            이 부분에 추가로 score에 가중치 주는 부분 이후에 추가
            '''
        return score

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
            guid_score += 0
        else:
            s_guid = hashlib.md5(dict_s['pe_pdb_GUID'].encode()).hexdigest()
            t_guid = hashlib.md5(dict_t['pe_pdb_GUID'].encode()).hexdigest()
            if s_guid == t_guid:
                guid_score += 1
            else:
                guid_score += 0
        if dict_s['pe_pdb_Pdbpath'] == "" or dict_t['pe_pdb_Pdbpath'] == "":
            path_score += 0
        else:
            path_score += NGram.compare(dict_s['pe_pdb_Pdbpath'], dict_t['pe_pdb_Pdbpath'], N=2)

        #score = (guid_score + path_score)
        score = str(guid_score)+','+str(path_score)

        return score

    def analyze_rsrc(self, standard, target):
        '''
        리소스 데이터를 각각 ssdeep으로 비교해서 결과를 반환하는 함수
        :return: score list with weight
        '''
        #print(json.dumps(standard, indent=4))
        #print(json.dumps(target, indent=4))

        #for i in range(len(standard)):
            #for j in range(len(target)):
                #if standard[i]

    def analyze_rich(self, standard, target):
        '''
        리치 헤더 데이터의 comid, count, prodid를 비교하는 함수
        *문자열로 뽑아서 한다면 ngram을, 데이터 자체를 뽑아서 한다며 data를 사용.. 재호랑 얘기해서하기
        :return: score with weight
        '''
        if standard['rich_info'] == {} or target['rich_info'] == {}:
            return 0
        else:
            if standard['rich_info'] == target['rich_info']:
                return 1
            else:
                return 0
        #print(json.dumps(standard, indent=4))
        #print(json.dumps(target, indent=4))

    def analyze_section(self, dict_s, dict_t):
        '''
        section 별 정보를
        *값이 다 작은 거라서 비교 알고리즘을 쓰기도 모호하고.. 훈이랑 얘기해봐야 할듯
        :return: score with weight
        '''
        comp = 0
        for key in dict_s.keys() and dict_t.keys():                                 #키의 이름이 다를 때의 예외처리가 필요
            if key in dict_s and key in dict_t:
                if dict_s[key]['section_name'] == dict_t[key]['section_name']:
                    print(f"{dict_s[key]['section_name']}, {dict_t[key]['section_name']}")
                    score = ssdeep.compare(dict_s[key]['hash_ssdeep'], dict_t[key]['hash_ssdeep'])
                    comp += score
                # print(f"{key} :: {score}")
                # 섹션 이름이 다르면 그 전까지의 섹션별 비교 수치는 버려야 하나 가져가야 하나?
                # if key in dict_s == key in dict_t:
                #     score = ssdeep.compare(dict_s[key]['hash_ssdeep'], dict_t[key]['hash_ssdeep'])
                #     comp += score
                # #print(f"{key} :: {score}")
                # # 섹션 이름이 다르면 그 전까지의 섹션별 비교 수치는 버려야 하나 가져가야 하나?
            else:
                continue
        return comp

    def analyze_all(self, pe_list):

        pe_all = OrderedDict()

        for index_1, pe_info_s in enumerate(pe_list):
            pe_s = OrderedDict()
            for index_2, pe_info_t in enumerate(pe_list):
                pe_t = OrderedDict()
                if index_1 == index_2:
                    continue
                #pe_t['filehash'] = hashlib.sha256(open(pe_info_t['file_name'], 'rb').read()).hexdigest()
                pe_t['file_hash'] = pe_info_t['file_hash']
                pe_t['time_date_stamp'] = pe_info_t['time_date_stamp']
                pe_t['imphash'] = self.analyze_imphash(pe_info_s, pe_info_t)
                pe_t['rich'] = self.analyze_rich(pe_info_s, pe_info_t)
                #print(f"{pe_info_s['file_name']} vs {pe_info_t['file_name']}")
                pe_t['section_score'] = self.analyze_section(pe_info_s['cmp_section'], pe_info_t['cmp_section'])
                #print("")
                pe_t['auth_score'] = self.analyze_auth(pe_info_s['auto'], pe_info_t['auto'])
                pe_t['pdb_score'] = self.analyze_pdb(pe_info_s['pdb_info'], pe_info_t['pdb_info'])
                #pe_t['rsrc'] = self.analyze_rsrc(pe_info_s['rsrc_info'], pe_info_t['rsrc_info'])
                pe_s[pe_info_t['file_name']] = pe_t
            pe_all[pe_info_s['file_name']] = pe_s

        return pe_all





