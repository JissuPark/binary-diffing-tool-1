import copy
import json
import operator
import timeit

from Main_engine.Analzer_Engine.Algorithm import all_algo as algo
from Main_engine.Analzer_Engine import whitelist_bbhs as white
from collections import OrderedDict
from ngram import NGram


class AnalyzeFlowchart:
    def __init__(self, idb_all):
        self.idb_all = idb_all
        self.idb_list = list()

        idb_dict = sorted(self.idb_all.items(), key=operator.itemgetter(0))
        for f_name, f_info in idb_dict:
            self.idb_list.append(f_info)

    def parser_bbh(self, bloc_dict):
        ### s = timeit.default_timer()

        file_name = bloc_dict["file_name"]
        print(f'[info] {file_name} WhiteList Filtering & Block hash/constants SET Create')
        block_hash_dic = dict()
        matched_dic = dict()
        block_constants_dic = dict()
        whitelist_matched_dic = dict()

        for x in bloc_dict["func_name"]:
            block_hash_dic[x] = dict()
            block_constants_dic[x] = dict()
            matched_dic[x] = dict()

            for y in bloc_dict["func_name"][x]:

                if y != "flow_opString" and y != "flow_constants" and y != "flow_branches":

                    block_hash = bloc_dict["func_name"][x][y]["block_sha256"]
                    if block_hash in white.list:
                        # print(f'[sensing] white_list -> {block_hash} : {white.list[block_hash]}')
                        matched_dic[x].update({y: {block_hash: white.list[block_hash]}})
                    else:
                        block_hash_dic[x].update({y: {block_hash: False}})
                        temp_dic = dict()
                        for constant in bloc_dict['func_name'][x][y]['block_constant'].split(' '):
                            if constant in temp_dic:
                                temp_dic[constant] += 1
                                continue
                            else:
                                temp_dic.update({constant: 1})
                                continue
                            temp_dic.update({constant: 1})
                        block_constants_dic[x].update({y: temp_dic})
                        del temp_dic

            if not matched_dic[x]:
                del matched_dic[x]
            if not block_hash_dic[x]:
                del block_hash_dic[x]
            if not block_constants_dic[x]:
                del block_constants_dic[x]

        ### print(f'[info] END block hash set & filter_list : {timeit.default_timer() - s}')

        # [variable_information] #
        # whitelist_matched_dic (type: dict) #
        # 한 바이너리의 블록해시들 중 whitelist에 매칭된 블록정보들을 담고있음.
        # 코드를 활성화 -> whitelist_matched_dic.update({file_name: matched_dic})
        whitelist_matched_dic.update({file_name: matched_dic})

        # white_list에 매칭된 블럭의 수를 카운트하려면 아래 코드를 활성화

        '''
        matched_count = 0
        for a, b in whitelist_matched_dic.items():
            for c, d in b.items():
                matched_count += len(d)
        print(f'[debug] white_list matched count : {matched_count}')
        '''

        bbh_result_dic = dict()
        bbh_result_dic[file_name] = dict()
        bbh_result_dic[file_name].update({"bbh": block_hash_dic})
        bbh_result_dic[file_name].update({"constant": block_constants_dic})

        return bbh_result_dic, whitelist_matched_dic

    def parser_bbh_T_F(self, _hash_dict, match_flag=False):
        # print(f'[debug] match_flag : {match_flag}')
        real_hash_dict = _hash_dict
        file_name = list(_hash_dict.keys())[0]

        # create False hash set
        if match_flag == 0:
            false_dic = copy.deepcopy(_hash_dict)
            for func_name, val_1 in real_hash_dict[file_name].items():
                for startAddr, val_2 in val_1.items():
                    for block_hash, flag in val_2.items():
                        if flag == 1:
                            del false_dic[file_name][func_name][startAddr][block_hash]
                    if not false_dic[file_name][func_name][startAddr]:
                        del false_dic[file_name][func_name][startAddr]
                if not false_dic[file_name][func_name]:
                    del false_dic[file_name][func_name]
            return false_dic

        # create True hash set
        elif match_flag == 1:
            true_dic = copy.deepcopy(_hash_dict)
            for func_name, val_1 in real_hash_dict[file_name].items():
                for startAddr, val_2 in val_1.items():
                    for block_hash, flag in val_2.items():
                        if flag == 0:
                            del true_dic[file_name][func_name][startAddr][block_hash]
                    if not true_dic[file_name][func_name][startAddr]:
                        del true_dic[file_name][func_name][startAddr]
                if not true_dic[file_name][func_name]:
                    del true_dic[file_name][func_name]
            return true_dic

    def compare_bbh(self, s_flow_data, t_flow_data):
        print(type(s_flow_data))
        s_name = list(s_flow_data.keys())[0]
        t_name = list(t_flow_data.keys())[0]

        s_hash_dict = copy.deepcopy(s_flow_data)
        t_hash_dict = copy.deepcopy(t_flow_data)

        print(f'[info] Compare Block hash SET ({s_name} ↔ {t_name})')
        matched_block_dic = dict()

        for s_fname, s_valueSet in s_hash_dict[s_name]['bbh'].items():
            matched_block_dic[s_fname] = dict()
            for s_sAddr, s_hashSet in s_valueSet.items():
                for s_hash in s_hashSet:
                    for t_fname, t_valueSet in t_hash_dict[t_name]['bbh'].items():
                        for t_sAddr, t_hashSet in t_valueSet.items():
                            for t_hash in t_hashSet:
                                if s_hash == t_hash and s_hashSet[s_hash] == 0 and t_hashSet[t_hash] == 0:
                                    s_hashSet[s_hash] = True
                                    t_hashSet[t_hash] = True
                                    const_sim = self.compare_bb_constants(list([s_fname, s_sAddr]), list([t_fname, t_sAddr]), \
                                                                     s_hash_dict[s_name]["constant"],
                                                                     t_hash_dict[t_name]["constant"])
                                    matched_block_dic[s_fname].update({s_sAddr: {t_fname + "-" + t_sAddr: const_sim}})

            if not matched_block_dic[s_fname]:
                del matched_block_dic[s_fname]

        # pprint(matched_block_dic)

        # parser_bbh_T_F(dict({s_name: s_hash_dict}))
        # parser_bbh_T_F(dict({t_name: t_hash_dict}))

        return dict({s_name: s_hash_dict[s_name]['bbh']}), dict({t_name: t_hash_dict[t_name]['bbh']}), matched_block_dic


    def compare_bb_constants(self, stand_list, target_list, s_hash_dict, t_hash_dict):

        s_fname, s_sAddr = stand_list
        t_fname, t_sAddr = target_list
        ##################################################################################################################
        s_const_set = s_hash_dict[s_fname][s_sAddr]
        t_const_set = t_hash_dict[t_fname][t_sAddr]
        ##################################################################################################################
        s_comp_set = copy.deepcopy(s_const_set)
        t_comp_set = copy.deepcopy(t_const_set)
        ##################################################################################################################
        matched = 0
        total_len = 0
        ##################################################################################################################
        # 상세 비교 전 dict 통째 비교 전처리
        if s_const_set == t_const_set:
            return 1.0
        else:
            total_len = sum(list(s_const_set.values())) + sum(list(t_const_set.values()))

            for s_const in s_const_set:
                for t_const in t_const_set:
                    if s_const == t_const:
                        temp = s_const_set[s_const] - t_const_set[t_const]
                        if temp == 0:
                            matched += s_const_set[s_const] + t_const_set[t_const]
                            del s_comp_set[s_const]
                            del t_comp_set[t_const]
                        elif temp < 0:
                            matched += (s_const_set[s_const] * 2)
                            t_comp_set[t_const] = t_comp_set[t_const] - s_comp_set[s_const]
                            del s_comp_set[s_const]
                        elif temp > 0:
                            matched += t_const_set[t_const]
                            s_comp_set[s_const] = s_comp_set[s_const] - t_comp_set[t_const]
                            del t_comp_set[t_const]

            # print(f" total: {total_len}  matched: {matched}  sim: {matched/total_len}")
            # pprint(s_comp_set)
            # pprint(t_comp_set)
            # print(" ************************** ")
            '''
            print(s_hash_dict[s_fname][s_sAddr])
            print(f"ㄴ[debug] stand_values : {sum(list(s_hash_dict[s_fname][s_sAddr].values()))}   {s_fname}-{s_sAddr}")
            <- <- <- <- <- <- 1칸 <- <- <- <- <- <-
            print(t_hash_dict[t_fname][t_sAddr])
            print(f"ㄴ[debug] stand_values : {sum(list(t_hash_dict[t_fname][t_sAddr].values()))}   {t_fname}-{t_sAddr}")
            '''
            #if (matched / total_len) < 1.0:
                #print(f"[debug] unmatched constants :: {s_hash_dict[s_fname][s_sAddr]} --- {t_hash_dict[t_fname][t_sAddr]}")
                #print(f"ㄴ[debug] constants find diff :: {s_comp_set} --- {t_comp_set}")
                #print(f" ")
        return round((matched / total_len), 2)

    def analyze_bbh(self, s_flow_data, t_flow_data):
        '''
        basic block hash(함수 대표값)을 비교해서 점수에 가중치를 매겨 반환하는 함수
        '''

        s_cmp_dic, whitelist_matched_dic = self.parser_bbh(s_flow_data)
        t_cmp_dic, whitelist_matched_dic = self.parser_bbh(t_flow_data)

        cmp_s, cmp_t, true_bb_const_sim = self.compare_bbh(s_cmp_dic, t_cmp_dic)

        return algo.get_func_similarity(cmp_s, )

    def analyze_constant(self, standard, target):
        const_score = algo.get_string_similarity(standard['constant'], target['constant'])
        return const_score['2-Gram']

    def analyze_all(self, yun_sorted_pe):

        idb_all = OrderedDict()

        for index_1, idb_info_s in enumerate(self.idb_list):
            idb_s = dict()
            yun_s = dict()
            for index_2, idb_info_t in enumerate(self.idb_list):
                idb_t = dict()

                if index_1 == index_2:
                    continue

                idb_t['bbh'] = self.analyze_bbh(idb_info_s, idb_info_t)
                idb_t['const_value'] = self.analyze_constant(idb_info_s, idb_info_t)

                idb_s[idb_info_t['file_name']] = idb_t

            idb_all[idb_info_s['file_name']] = idb_s

        return idb_all, yun_sorted_pe

