import hashlib
from collections import OrderedDict
import Analzer_Engine.analyzer_main as AM
import json
from Analzer_Engine.Algorithm import all_algo as algo


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
        for f_name, f_info in self.pe_all.items():
            pe_list.append(f_info)

        return pe_list

        # # 전체에 대한 dictionary 받아옴
        # self.result_list = list()
        #
        # print(result)
        # for i in result.values():
        #     self.result_list.append(i)
        # for j in self.result_list:
        #     print(j)
        #
        # # data 파싱
        # for rs_value in self.result_list[0].values():
        #     for rs_key in rs_value:
        #         if rs_key == 'imp_hash':
        #             self.s_imp_hash = rs_value['imp_hash']
        #         elif rs_key == 'rich_info(xor_key)':
        #             self.s_xor_key = rs_value['rich_info(xor_key)']
        #         elif rs_key == 'cmp_section':
        #             print(rs_value['cmp_section'])
        #
        # for rs_value in self.result_list[1].values():
        #     for rs_key in rs_value:
        #         if rs_key == 'imp_hash':
        #             self.t_imp_hash = rs_value['imp_hash']
        #         elif rs_key == 'rich_info(xor_key)':
        #             self.t_xor_key = rs_value['rich_info(xor_key)']

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



    def analyze_auth(self):
        '''
        인증서의 data 자체를 ssdeep으로 비교해서 얼마나 같은지 계산해 반환하는 함수
        :return: score with weight
        '''

    def analyze_rsrc(self, standard, target):
        '''
        리소스 데이터를 각각 ssdeep으로 비교해서 결과를 반환하는 함수
        :return: score list with weight
        '''
        if self.s_language == self.t_language:
            return 1
        else:
            return 0

    def analyze_rich(self, standard, target):
        '''
        리치 헤더 데이터의 comid, count, prodid를 비교하는 함수 
        *문자열로 뽑아서 한다면 ngram을, 데이터 자체를 뽑아서 한다며 data를 사용.. 재호랑 얘기해서하기
        :return: score with weight
        '''
        if standard['rich_info(xor_key)'] == target['rich_info(xor_key)']:
            return 1
        else:
            return 0

    def analyze_section(self):
        '''
        section 별 정보를
        *값이 다 작은 거라서 비교 알고리즘을 쓰기도 모호하고.. 훈이랑 얘기해봐야 할듯
        :return: score with weight
        '''

        total_cnt = len(self.s_section_hash)
        cnt = 0
        for s in self.s_section_hash:
            for t in self.t_section_hash:
                if s == t:
                    cnt += 1
        return cnt/total_cnt

    def analyze_all(self, pe_list):

        pe_all = OrderedDict()

        for index_1, pe_info_s in enumerate(pe_list):
            pe_s = OrderedDict()
            for index_2, pe_info_t in enumerate(pe_list):
                pe_t = OrderedDict()
                if index_1 == index_2:
                    continue
                #pe_t['hash'] = pe_info_s.keys()
                #for value in pe_info_s.values() if value == ''
                pe_t['filehash'] = hashlib.sha256(open(pe_info_t['file_name'], 'rb').read()).hexdigest()
                pe_t['imphash'] = self.analyze_imphash(pe_info_s, pe_info_t)
                pe_t['rich'] = self.analyze_rich(pe_info_s, pe_info_t)
                #pe_t['rsrc'] = pe.analyze_rsrc(pe_info_s, pe_info_t)
                pe_s[pe_info_t['file_name']] = pe_t
            pe_all[pe_info_s['file_name']] = pe_s
        return pe_all





