

class AnalyzeSimilarity:
    def __init__(self, S_PATH, T_PATH):
        self.stand_path = S_PATH                #기준이 되는 데이터의 경로
        self.target_path = T_PATH               #대상이 되는 데이터의 경로

    def analyze_parser(self):
        '''
        PATH에 있는 데이터를 받아서 각 class에 넣을 수 있게 파싱해주는 함수
        디비로 받든 json으로 받던지 하나의 input이 들어오면 각 class를 불러서 객체를 만들어 주는 함수
        :return: none
        '''

        ############################
        #   PE랑 flowchart로 나누기  #       => 각각 다른 파일로 줄거라서 필요 없어짐
        ############################

        # 나눈 애들 각 클래스에 인자로 넣어서 객체 만들어서 반환하기
        # self.P = analyze_pe.AnalyzePE()
        # self.F = analyze_flowchart.AnalyzeFlowchart()
        print('[+] Json file parsing complete!')

    def calculate_heuristic(self):
        '''
        가중치가 부여된 점수들을 더해서 반환해주는 함수
        *다 더했을 때 최대나 최소안에 있는지 확인하는 로직을 넣어주고 예외처리 해주면 될 듯
        :return: final score
        '''
        # 최종 휴리스틱 스코어
        final_score = 0

        # Flowchart 점수 추가 (가중치 포함)
        self.F.Flow_parser()
        final_score += self.F.analyze_filehash()
        final_score += self.F.analyze_bbh()
        final_score += self.F.analyze_constant()

        # 이건 파일 해쉬가 같으면 같은 파일이니까 넘기는 부분인데 여기 있으면 효율 개떨어지는데?
        # if 100 is self.F.analyze_filehash():
        #     final_score = 100
        #     return final_score

        # PE 점수 추가 (가중치 포함)
        self.P.PE_parser()
        final_score += self.P.analyze_auth()
        final_score += self.P.analyze_imphash()
        final_score += self.P.analyze_pdb()
        final_score += self.P.analyze_rich()
        final_score += self.P.analyze_rsrc()

        # 최종 점수가 0이상 100이하인지 확인
        if not 0<= final_score <=100:
            print('There is something wrong, buddy!')
            exit(-1)
        # 확인됐으면 반환
        return final_score

#############################################################
#   전역 비교 함수                                             #
#   각 클래스에서 파싱된 data를 인자로 받음                        #
#   이렇게 하는 이유는 똑같이 계산해 주는 함수가 있으면               #
#   분석하는 클래스안의 함수들은 가중치만 더해서 반환해줄 수 있으므로    #
#############################################################


# 이대로 완성된다면 main 코드는 이게 전부임
if __name__ == "__main__":
    print('==========================START MAIN==========================')

    # Analyzer = AnalyzeSimilarity(path_stand,path_target)
    # Analyzer.analyze_parser()
    # Analyzer.calculate_heuristic()