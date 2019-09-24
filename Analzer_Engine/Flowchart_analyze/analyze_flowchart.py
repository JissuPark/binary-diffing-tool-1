import Analzer_Engine.Analyzer_main as AM


class AnalyzeFlowchart:
    def __init__(self, S_FLOW, T_FLOW):
        '''
        flawchart 데이터를 받아오면 변수로 저장해주는 생성자
        :param: S_FLOW:
        :param: T_FLOW:
        '''
        self.stand_flow = S_FLOW
        self.target_flow = T_FLOW

    def Flow_parser(self):
        '''
        Flowchart 데이터가 들어오면 function hash, basic block hash, constant value로 파싱해서
        각 함수에서 사용할 수 있게 해주는 함수
        :return: none
        '''

    def analyze_bbh(self):
        '''
        basic block hash(함수 대표값)을 비교해서 점수에 가중치를 매겨 반환하는 함수
        :return: score with weight
        '''
        AM.cmp_hash()

    def analyze_filehash(self):
        '''
        file 자체의 hash 값을 비교해주는 함수
        *파일의 해쉬값을 먼저 계산했으므로 비교만하면 된다. cmp_hash 불필요
        :return: score with weight
        '''

    def analyze_constant(self):
        '''
        상수값을 비교해주는 함수
        :return: score with weight
        '''
        AM.cmp_ngarm()