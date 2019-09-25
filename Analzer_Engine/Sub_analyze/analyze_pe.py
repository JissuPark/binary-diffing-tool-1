import Analzer_Engine.Analyzer_main as AM
import json
from Analzer_Engine.Algorithm import all_algo as algo


class AnalyzePE:
    def __init__(self):
        '''
        PE data를 받아오면 변수로 저장해주는 생성자 
        :param: S_PE : data piece about PE of stand data from input 
        :param: T_PE : data piece about PE of stand data from input 
        '''



    def PE_parser(self, RESULT):
        '''
        PE data가 들어오면 rsrc, rich, pdb로 파싱해서 각 함수에서 사용할 수 있게 해주는 함수
        *파싱만 잘해서 넘겨주면 각 함수는 크게 할 일이 없고 cmp함수 호출해서 나오는 결과에 따라 가중치만 부여해주면 됨
        :return: none
        '''
        with open(RESULT) as result_json:
            self.result_data = json.load(result_json)

        # 전체에 대한 dictionary 받아옴
        self.result_list = list()
        print(self.result_data)
        for i in self.result_data.values():
            self.result_list.append(i)
        for j in self.result_list:
            print(j)

        # data 파싱
        for rs_value in self.result_list[0].values():
            for rs_key in rs_value:
                if rs_key == 'imp_hash':
                    self.s_imp_hash = rs_value['imp_hash']
                elif rs_key == 'rich_info(xor_key)':
                    self.s_xor_key = rs_value['rich_info(xor_key)']
                elif rs_key == 'cmp_section':
                    print(rs_value['cmp_section'])

        for rs_value in self.result_list[1].values():
            for rs_key in rs_value:
                if rs_key == 'imp_hash':
                    self.t_imp_hash = rs_value['imp_hash']
                elif rs_key == 'rich_info(xor_key)':
                    self.t_xor_key = rs_value['rich_info(xor_key)']

    def analyze_imphash(self):
        '''
        PE에서 imphash를 뽑아서 비교해 참/거짓에 따라 점수를 반환하는 함수
        *hash 값 하나짜리라 cmp_hash를 쓸 필요가 없음
        :return: score with weight
        '''

        if self.s_imp_hash == self.t_imp_hash:
            return 1
        else:
            return 0



    def analyze_auth(self):
        '''
        인증서의 data 자체를 ssdeep으로 비교해서 얼마나 같은지 계산해 반환하는 함수
        :return: score with weight
        '''

    def analyze_rsrc(self):
        '''
        리소스 데이터를 각각 ssdeep으로 비교해서 결과를 반환하는 함수
        :return: score list with weight
        '''
        if self.s_language == self.t_language:
            return 1
        else:
            return 0

    def analyze_rich(self):
        '''
        리치 헤더 데이터의 comid, count, prodid를 비교하는 함수 
        *문자열로 뽑아서 한다면 ngram을, 데이터 자체를 뽑아서 한다며 data를 사용.. 재호랑 얘기해서하기
        :return: score with weight
        '''
        if self.s_xor_key == self.t_xor_key:
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



