from ngram import NGram

import Analzer_Engine.Analyzer_main as AM
from Extract_Engine.PE_feature import Pe_Pdb
from Analzer_Engine.Flowchart_analyze import func_ngram



class AnalyzePE:
    def __init__(self, S_PE, T_PE):
        '''
        PE data를 받아오면 변수로 저장해주는 생성자 
        :param: S_PE : data piece about PE of stand data from input 
        :param: T_PE : data piece about PE of stand data from input 
        '''
        self.stand_pe = S_PE
        self.target_pe = T_PE

    def PE_parser(self):
        '''
        PE data가 들어오면 rsrc, rich, pdb로 파싱해서 각 함수에서 사용할 수 있게 해주는 함수
        *파싱만 잘해서 넘겨주면 각 함수는 크게 할 일이 없고 cmp함수 호출해서 나오는 결과에 따라 가중치만 부여해주면 됨
        :return: none
        '''

    def analyze_imphash(self):
        '''
        PE에서 imphash를 뽑아서 비교해 참/거짓에 따라 점수를 반환하는 함수
        *hash 값 하나짜리라 cmp_hash를 쓸 필요가 없음
        :return: score with weight
        '''

    def analyze_auth(self):
        '''
        인증서의 data 자체를 ssdeep으로 비교해서 얼마나 같은지 계산해 반환하는 함수
        :return: score with weight
        '''
        AM.cmp_data()

    def analyze_rsrc(self):
        '''
        리소스 데이터를 각각 ssdeep으로 비교해서 결과를 반환하는 함수
        :return: score list with weight
        '''
        AM.cmp_data()

    def analyze_rich(self):
        '''
        리치 헤더 데이터의 comid, count, prodid를 비교하는 함수 
        *문자열로 뽑아서 한다면 ngram을, 데이터 자체를 뽑아서 한다며 data를 사용.. 재호랑 얘기해서하기
        :return: score with weight
        '''
        AM.cmp_data()
        AM.cmp_ngarm()

    def analyze_pdb(self):
        '''
        이름, guid, age, 경로를 비교해주는 함수
        *값이 다 작은 거라서 비교 알고리즘을 쓰기도 모호하고.. 훈이랑 얘기해봐야 할듯
        :return: score with weight
        '''
