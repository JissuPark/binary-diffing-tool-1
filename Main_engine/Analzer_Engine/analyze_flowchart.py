import json
import operator
import timeit

from Main_engine.Analzer_Engine.Algorithm import all_algo as algo
from Main_engine.Analzer_Engine import whitelist_bbhs as white
from collections import OrderedDict
from ngram import NGram


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

        idb_dict = sorted(self.idb_all.items(), key=operator.itemgetter(0))
        for f_name, f_info in idb_dict:
            idb_list.append(f_info)

        return idb_list

    def block_hash_parser(self, bloc_dict):
        s = timeit.default_timer()  # start time
        print(f'[info] Making Block hash SET & Filter White List')
        block_hash_dic = dict()

        for x in bloc_dict["func_name"]:
            block_hash_dic[x] = {}
            for y in bloc_dict["func_name"][x]:
                if y != "flow_opString":
                    # 화이트 리스트 처리는 이 부분에서..?
                    # 해당 코드 로직 개선해야합니다(후순위) - 현목 -
                    try:
                        if bloc_dict["func_name"][x][y]['block_sha256'] in white.list:
                            continue
                        block_hash_dic[x].update({y: {bloc_dict["func_name"][x][y]['block_sha256']: False}})
                    except:
                        continue
        print(f'[info] END block hash set & filter_list : {timeit.default_timer() - s}')
        return block_hash_dic

    def analyze_bbh(self, s_flow_data, t_flow_data):
        '''

        basic block hash(함수 대표값)을 비교해서 점수에 가중치를 매겨 반환하는 함수
        :return: score with weight
        '''

        s_hash_dict = self.block_hash_parser(s_flow_data)
        t_hash_dict = self.block_hash_parser(t_flow_data)
        stand_hash_count = 0
        # cmp_dict = dict()
        target_dict = dict()
        stand_dict = dict()

        stand_f = OrderedDict()
        target_f = OrderedDict()
        # cmp_func_all = list()
        # cmp_straddr_all = list()
        cmp_func_list = list()
        cmp_straddr_list = list()
        correction_score = 0

        for s_fname, s_valueSet in s_hash_dict.items():
            stand_list = list()
            for s_sAddr, s_hashSet in s_valueSet.items():
                for s_hash in s_hashSet:
                    stand_hash_count += 1
                    for t_fname, t_valueSet in t_hash_dict.items():
                        target_list = list()
                        for t_tAddr, t_hashSet in t_valueSet.items():

                            for t_hash in t_hashSet:
                                if s_hash == t_hash:
                                    s_hashSet[s_hash] = True
                                    t_hashSet[t_hash] = True
                                    # ================================ #
                                    # cmp_func_list.append(s_fname)
                                    # cmp_func_list.append(t_fname)
                                    # cmp_func_all.append(cmp_func_list)
                                    # cmp_straddr_list.append(s_sAddr)
                                    # cmp_straddr_list.append(t_tAddr)
                                    # cmp_straddr_all.append(cmp_straddr_list)
                                    stand_list.append(s_sAddr)
                                    stand_dict[s_fname] = stand_list
                                    target_list.append(t_tAddr)
                                    target_dict[t_fname] = target_list
                                    # ================================ #
                                else:
                                    if s_hashSet[s_hash] == False and t_hashSet[t_hash] == False:
                                        sim = NGram.compare(' '.join(s_flow_data['func_name'][s_fname][s_sAddr]['opcodes']),\
                                                            ' '.join(t_flow_data['func_name'][t_fname][t_tAddr]['opcodes']), N=3)
                                        if sim > 0.89:
                                            # 유사블럭 보정점수 모아서 리턴,
                                            # 따로 유사블럭에 대한 Flag는 변경하지 않음. 추후 필요하면 추가
                                            correction_score = correction_score + 1
                                            #print(f'stand : {s_fname}-{s_sAddr} ::: target : {t_fname}-{t_tAddr} ::::: {sim}')

        stand_f[s_flow_data['file_name']] = stand_dict
        target_f[t_flow_data['file_name']] = target_dict

        stand_f.update(target_f)

        #
        with open(r"C:\malware\result\dict_test.txt", 'a') as makefile:
            json.dump(stand_f, makefile, ensure_ascii=False, indent='\t')
        # pprint.pprint(stand)
        # print('-----------------------------------------------------------------------')
        # pprint.pprint(tar)
        # print('=================================================================================')
        # print(json.dumps(s_hash_dict, indent=4))
        # print('-----------------------------------------------------------------------')
        # print(json.dumps(t_hash_dict, indent=4))
        return algo.get_func_similarity(s_hash_dict, t_hash_dict, stand_hash_count, correction_score),\
               cmp_func_list, cmp_straddr_list

    def analyze_constant(self, standard, target):
        '''

        상수값을 비교해서 점수에 가중치를 매겨 반환하는 함수
        :return: score with weight
        '''

        const_score = algo.get_string_similarity(standard['constant'], target['constant'])
        return const_score['2-Gram']

    def analyze_all(self, idb_list, yun_sorted_pe):
        flag = 0
        idb_all = OrderedDict()
        yun_all = dict()
        for var in yun_sorted_pe:
            print(f"yun_sorted_pe ::  {var}")
        #for key in yun_sorted_pe.items():
            #print(f"yun_sorted_pe's keys are :: {key}")
        for index_1, idb_info_s in enumerate(idb_list):
            idb_s = dict()
            yun_s = dict()
            for index_2, idb_info_t in enumerate(idb_list):
                idb_t = dict()
                test_d = dict()
                yun = dict()
                if index_1 == index_2:
                    continue
                idb_t['bbh'], test_d['func_name'], test_d['start_addr'] = self.analyze_bbh(idb_info_s, idb_info_t)

                ######   연대기 추가  ######
                for var in yun_sorted_pe:
                    print("found :: ", var)
                    if idb_t['bbh'] >= 0.85:
                        yun_s['comp_file_name'] = idb_info_t['file_name']
                        yun_s['comp_bbh'] = idb_t['bbh']
                        yun_sorted_pe[idb_info_s['file_name']].update(yun_s)
                ############################

                idb_t['const_value'] = self.analyze_constant(idb_info_s, idb_info_t)
                idb_s[idb_info_t['file_name']] = idb_t

            idb_all[idb_info_s['file_name']] = idb_s

        #print(json.dumps(yun_all, indent=4))
        # with open(r"C:\malware\result\cm_test.txt", 'w') as makefile:
        #     json.dump(test_all, makefile, ensure_ascii=False, indent='\t')
        #print(f"idb_all :: {json.dumps(idb_all,indent=4)}")
        print(f"yun_all :: {json.dumps(yun_sorted_pe, indent=4)}")
        return idb_all, yun_sorted_pe