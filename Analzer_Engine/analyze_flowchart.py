import hashlib

from Analzer_Engine.Algorithm import all_algo as algo
from collections import OrderedDict

class AnalyzeFlowchart:
    def __init__(self, idb_all):
        '''
        flawchart 데이터를 받아오면 변수로 저장해주는 생성자
        :param: S_FLOW:
        :param: T_FLOW:
        '''
        self.idb_all = idb_all
        # self.stand_flow = S_FLOW
        # self.target_flow = T_FLOW
        # self.s_hash_dict = dict()
        # self.t_hash_dict = dict()
        # self.s_constant = ""
        # self.t_constant = ""

    def flow_parser(self):
        '''
        Flowchart 데이터가 들어오면 basic block hash, constant value 로 파싱해서
        각 함수에서 사용할 수 있게 해주는 함수
        :return: none
        '''

        idb_list = list()
        for f_name, f_info in self.idb_all.items():
            idb_list.append(f_info)

        return idb_list

    def block_hash_parser(self, bloc_dict):
        block_hash_dic = dict()

        for x in bloc_dict["func_name"]:
            block_hash_dic[x] = {}
            for y in bloc_dict["func_name"][x]:
                if y != "flow_opString":
                    # 화이트 리스트 처리는 이 부분에서..?
                    block_hash_dic[x].update({y: {bloc_dict["func_name"][x][y]['block_sha256']: False}})

        return block_hash_dic


    def analyze_bbh(self, s_flow_data, t_flow_data):
        '''

        basic block hash(함수 대표값)을 비교해서 점수에 가중치를 매겨 반환하는 함수
        :return: score with weight
        '''

        s_hash_dict = self.block_hash_parser(s_flow_data)
        t_hash_dict = self.block_hash_parser(t_flow_data)
        stand_hash_count = 0

        for s_fname, s_valueSet in s_hash_dict.items():
            for s_sAddr, s_hashSet in s_valueSet.items():
                for s_hash in s_hashSet:
                    stand_hash_count += 1
                    for t_fname, t_valueSet in t_hash_dict.items():
                        for t_tAddr, t_hashSet in t_valueSet.items():
                            for t_hash in t_hashSet:
                                if s_hash == t_hash:
                                    s_hashSet[s_hash] = True
                                    t_hashSet[t_hash] = True
        # pprint.pprint(stand)
        # print('-----------------------------------------------------------------------')
        # pprint.pprint(tar)

        return algo.get_func_similaridty(s_hash_dict, t_hash_dict, stand_hash_count)

    def analyze_constant(self,standard, target):
        '''

        상수값을 비교해서 점수에 가중치를 매겨 반환하는 함수
        :return: score with weight
        '''

        const_score = algo.get_string_similarity(standard['constant'], target['constant'])
        return const_score['2-Gram']

    def analyze_all(self, idb_list):
        idb_all = OrderedDict()

        for index_1, idb_info_s in enumerate(idb_list):
            idb_s = dict()
            for index_2, idb_info_t in enumerate(idb_list):
                idb_t = dict()
                if index_1 == index_2:
                    continue
                idb_t['bbh'] = self.analyze_bbh(idb_info_s, idb_info_t)
                idb_t['const_value'] = self.analyze_constant(idb_info_s, idb_info_t)
                idb_s[idb_info_t['file_name']] = idb_t
            idb_all[idb_info_s['file_name']] = idb_s
        return idb_all
