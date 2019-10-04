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

        # # flow json 파일 가져와서 읽기
        # with open(self.stand_flow) as s_flow_json:
        #     s_flow_data = json.load(s_flow_json)
        # with open(self.target_flow) as t_flow_json:
        #     t_flow_data = json.load(t_flow_json)
        #
        # # 함수 이름 추출
        # self.s_func_list = [key for key in s_flow_data if key != 'constant']
        # self.t_func_list = [key for key in t_flow_data if key != 'constant']
        #
        # # hash & constant value 추출
        # for func in s_flow_data:
        #     # constant value
        #     if func == 'constant':
        #         self.s_constant = s_flow_data[func]
        #         continue
        #     for basic_block in s_flow_data[func]:
        #         if basic_block == 'flow_opString':
        #             continue
        #         self.s_hash_dict.update({s_flow_data[func][basic_block]['block_sha256']: False})
        #
        # for func in t_flow_data:
        #     # except constant value
        #     if func == 'constant':
        #         self.t_constant = t_flow_data[func]
        #         continue
        #     for basic_block in t_flow_data[func]:
        #         if basic_block == 'flow_opString':
        #             continue
        #         self.t_hash_dict.update({t_flow_data[func][basic_block]['block_sha256']: False})

    def analyze_bbh(self, s_flow_data, t_flow_data):
        '''

        basic block hash(함수 대표값)을 비교해서 점수에 가중치를 매겨 반환하는 함수
        :return: score with weight
        '''

        s_hash_dict = dict()
        t_hash_dict = dict()

        for func in s_flow_data:
            # constant value
            if func != 'constant' and func != 'file_name':
                for basic_block in s_flow_data[func]:
                    for basic_block2 in s_flow_data[func][basic_block]:
                        if basic_block2 != 'flow_opString':
                            s_hash_dict.update({s_flow_data[func][basic_block][basic_block2]['block_sha256']: False})

        for func in t_flow_data:
            # except constant value
            if func != 'constant' and func != 'file_name':
                for basic_block in t_flow_data[func]:
                    for basic_block2 in t_flow_data[func][basic_block]:
                        if basic_block2 != 'flow_opString':
                            t_hash_dict.update({t_flow_data[func][basic_block][basic_block2]['block_sha256']: False})

        bbh_score = algo.get_func_similarity(s_hash_dict, t_hash_dict)

        return bbh_score

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
