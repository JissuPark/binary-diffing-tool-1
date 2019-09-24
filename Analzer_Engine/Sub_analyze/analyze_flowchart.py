import json
from Analzer_Engine import Analyzer_main

class AnalyzeFlowchart:
    def __init__(self, S_FLOW, T_FLOW):
        '''
        flawchart 데이터를 받아오면 변수로 저장해주는 생성자
        :param: S_FLOW:
        :param: T_FLOW:
        '''
        self.stand_flow = S_FLOW
        self.target_flow = T_FLOW
        self.s_hash_dict = dict()
        self.t_hash_dict = dict()
        self.s_constant = ""
        self.t_constant = ""

    def Flow_parser(self):
        '''
        Flowchart 데이터가 들어오면 basic block hash, constant value 로 파싱해서
        각 함수에서 사용할 수 있게 해주는 함수
        :return: none
        '''

        # flow json 파일 가져와서 읽기
        with open(self.stand_flow) as s_flow_json:
            s_flow_data = json.load(s_flow_json)
        with open(self.target_flow) as t_flow_json:
            t_flow_data = json.load(t_flow_json)

        # 함수 이름 추출
        self.s_func_list = [key for key in s_flow_data if key != 'constant']
        self.t_func_list = [key for key in t_flow_data if key != 'constant']

        # hash & constant value 추출
        for func in s_flow_data:
            # constant value
            if func == 'constant':
                self.s_constant = s_flow_data[func]
                continue
            for basic_block in s_flow_data[func]:
                if basic_block == 'flow_opString':
                    continue
                self.s_hash_dict.update({s_flow_data[func][basic_block]['block_sha256']: False})

        for func in t_flow_data:
            # except constant value
            if func == 'constant':
                self.t_constant = t_flow_data[func]
                continue
            for basic_block in t_flow_data[func]:
                if basic_block == 'flow_opString':
                    continue
                self.t_hash_dict.update({t_flow_data[func][basic_block]['block_sha256']: False})

    def analyze_bbh(self):
        '''
        basic block hash(함수 대표값)을 비교해서 점수에 가중치를 매겨 반환하는 함수
        :return: score with weight
        '''


    def analyze_constant(self):
        '''
        상수값을 비교해주는 함수
        :return: score with weight
        '''



if __name__ == '__main__':
    print('==========================START FLOWCHART==========================')
    print('-------------------------------------------------------------------')
    path_stand = r"C:\Users\qkrwl\PycharmProjects\Breakers\binary-diffing-tool\test_01.txt"
    path_target = r"C:\Users\qkrwl\PycharmProjects\Breakers\binary-diffing-tool\test_02.txt"
    a = AnalyzeFlowchart(path_stand, path_target)
    print('--------------------------START PARSING----------------------------')
    a.Flow_parser()
    print(f'[+]Standard File\' function list : {a.s_func_list}')
    print(f'[+]Target File\' function list : {a.t_func_list}')
    print(f'[+]Standard File\' hash dictionary : {a.s_hash_dict}')
    print(f'[+]Target File\' hash dictionary : {a.t_hash_dict}')
    print(f'[+]Standard File\' constant value : {a.s_constant}')
    print(f'[+]Target File\' constant value : {a.t_constant}')
    print('-----------------------------END PARSER-----------------------------')