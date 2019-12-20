import copy
import json
import operator
import timeit

from Main_engine.Analzer_Engine.Algorithm import all_algo as algo
from Main_engine.Analzer_Engine import whitelist_bbhs as white
from Main_engine.Extract_Engine.Flowchart_feature import const_filter_indexs
from collections import OrderedDict
from fractions import Fraction
from ngram import NGram
from pprint import pprint

class AnalyzeFlowchart:
    def __init__(self, idb_all):
        self.idb_all = idb_all
        self.idb_list = list()

        idb_dict = sorted(self.idb_all.items(), key=operator.itemgetter(0))
        for f_name, f_info in idb_dict:
            self.idb_list.append(f_info)

    def parser_bbh(self, bloc_dict):
        file_name = bloc_dict["file_name"]
        # print(f'[info] {file_name} WhiteList Filtering & Block hash/constants SET Create')
        block_hash_dic = dict()
        matched_dic = dict()
        block_constants_dic = dict()
        whitelist_matched_dic = dict()
        flow_const_dict = dict()

        for x in bloc_dict["func_name"]:
            block_hash_dic[x] = dict()
            block_constants_dic[x] = dict()
            matched_dic[x] = dict()

            for y in bloc_dict["func_name"][x]:

                if y == "flow_constants":
                    flow_const_dict.update({x: bloc_dict["func_name"][x]["flow_constants"]})
                elif y != "flow_constants" and y != "flow_branches":
                    block_hash = bloc_dict["func_name"][x][y]['block_sha256']

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


        return bbh_result_dic, whitelist_matched_dic, flow_const_dict

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

    def get_cmp_priority(self, _dict, count_dict):

        priority_vote_dic = dict()
        for baseFunc in _dict:
            priority_vote_dic[baseFunc] = dict()
            for baseBB in _dict[baseFunc]:
                for targetFunc in _dict[baseFunc][baseBB]:
                    if targetFunc in priority_vote_dic[baseFunc]:
                        priority_vote_dic[baseFunc][targetFunc] = priority_vote_dic[baseFunc][targetFunc] + 1
                    else:
                        priority_vote_dic[baseFunc].update({targetFunc: 1})
            del baseFunc, baseBB, targetFunc

        matched_dict = dict()
        for baseFunc, value in priority_vote_dic.items():
            baseFunc_cnt = count_dict['base'][baseFunc]
            key_max = max(value.values())
            matched_dict[baseFunc] = dict()
            for targetFunc in value:
                if key_max == priority_vote_dic[baseFunc][targetFunc]:
                    targetFunc_cnt = count_dict['target'][targetFunc]
                    if baseFunc_cnt < key_max or targetFunc_cnt < key_max:
                        function_similarity = (key_max) / (baseFunc_cnt + targetFunc_cnt)
                    else:
                        function_similarity = (key_max * 2) / (baseFunc_cnt + targetFunc_cnt)
                    if function_similarity > 0.2:
                        matched_dict[baseFunc].update({targetFunc: function_similarity})
                        del function_similarity
            if not matched_dict[baseFunc]:
                del matched_dict[baseFunc]
        return matched_dict

    def compare_flow_const(self, base_flow_const, tar_flow_const):

        if base_flow_const == tar_flow_const:
            return 1.0
        else:
            return NGram.compare(' '.join(base_flow_const), ' '.join(tar_flow_const), N=2)

    def get_block_cnt(self, _dict):

        count_dict = dict()
        for funcName, value in _dict.items():
            bb_count = 0
            for basicblock, etc in value.items():
                bb_count = bb_count + 1
            count_dict.update({funcName: bb_count})
            del bb_count
        return count_dict

    def find_best(self, matched_dict, flow_const):

        mutex_dic = dict()
        find_best_dic = dict()

        for baseFunc in matched_dict:
            best = max(matched_dict[baseFunc].values())
            mutex_dic[baseFunc] = dict()
            for targetFunc in matched_dict[baseFunc]:
                if best == matched_dict[baseFunc][targetFunc]:
                    mutex_dic[baseFunc].update({targetFunc: self.compare_flow_const(flow_const['base'][baseFunc],
                                                                               flow_const['target'][targetFunc])})
        mutex_list = list()
        for baseFunc in mutex_dic:
            best = max(mutex_dic[baseFunc].values())
            for targetFunc in mutex_dic[baseFunc]:
                if best == mutex_dic[baseFunc][targetFunc]:
                    if baseFunc not in mutex_list and targetFunc not in mutex_list:
                        mutex_list.append(baseFunc)
                        mutex_list.append(targetFunc)
                        find_best_dic.update({baseFunc: targetFunc})

        return find_best_dic

    def get_function_similarity(self, count_dict, matched_info_dic, priority_dic):
        return_dic = dict()
        for baseFunc, targetFunc in priority_dic.items():
            base_count = count_dict['base'][baseFunc]
            target_count = count_dict['target'][targetFunc]
            matched_count = matched_info_dic[baseFunc][targetFunc]
            if matched_count / target_count > 0.25:
                # print(f'[Debug] {baseFunc}-{targetFunc} : {base_count}, {target_count} => {matched_count}({matched_count/target_count}%)')
                return_dic.update({baseFunc: {targetFunc: {base_count: {target_count: {matched_count: matched_count / target_count}}}}})
        return return_dic

    def compare_bbh(self, s_flow_data, t_flow_data, flow_const):

        s_name = list(s_flow_data.keys())[0]
        t_name = list(t_flow_data.keys())[0]
        # print(f'[info] Compare Block hash SET ({s_name} ↔ {t_name})')
        s_hash_dict = copy.deepcopy(s_flow_data)
        t_hash_dict = copy.deepcopy(t_flow_data)
        count_dict = dict()
        count_dict.update({"base": self.get_block_cnt(s_flow_data[s_name]['bbh'])})
        count_dict.update({"target": self.get_block_cnt(t_flow_data[t_name]['bbh'])})
        const_matched_bb_dic = dict()
        temp_matched_dic = dict()

        for s_fname, s_valueSet in s_hash_dict[s_name]['bbh'].items():
            temp_matched_dic[s_fname] = dict()
            for s_sAddr, s_hashSet in s_valueSet.items():
                temp_matched_dic[s_fname][s_sAddr] = dict()
                for s_hash in s_hashSet:
                    for t_fname, t_valueSet in t_hash_dict[t_name]['bbh'].items():
                        for t_sAddr, t_hashSet in t_valueSet.items():
                            for t_hash in t_hashSet:
                                if s_hash == t_hash:
                                    if t_fname in temp_matched_dic[s_fname][s_sAddr]:
                                        temp_list = temp_matched_dic[s_fname][s_sAddr][t_fname]
                                        temp_list.append(t_sAddr)
                                        temp_matched_dic[s_fname][s_sAddr].update({t_fname: temp_list})
                                        del temp_list
                                    else:
                                        temp_matched_dic[s_fname][s_sAddr].update({t_fname: [t_sAddr]})
                if not temp_matched_dic[s_fname][s_sAddr]:
                    del temp_matched_dic[s_fname][s_sAddr]
            if not temp_matched_dic[s_fname]:
                del temp_matched_dic[s_fname]

        classification = self.get_cmp_priority(temp_matched_dic, count_dict)
        priority_dic = self.find_best(classification, flow_const)

        matched_info_dic = dict()
        for baseFunc, tarFunc in priority_dic.items():
            count = 0
            const_matched_bb_dic[baseFunc] = dict()
            for base_block in s_hash_dict[s_name]['bbh'][baseFunc]:
                for base_hash in s_hash_dict[s_name]['bbh'][baseFunc][base_block]:
                    for target_block in t_hash_dict[t_name]['bbh'][tarFunc]:
                        for target_hash in t_hash_dict[t_name]['bbh'][tarFunc][target_block]:
                            if base_hash == target_hash and s_hash_dict[s_name]['bbh'][baseFunc][base_block][base_hash] == 0 \
                                    and t_hash_dict[t_name]['bbh'][tarFunc][target_block][target_hash] == 0:
                                s_hash_dict[s_name]['bbh'][baseFunc][base_block][base_hash] = True
                                t_hash_dict[t_name]['bbh'][tarFunc][target_block][target_hash] = True
                                const_sim = self.compare_bb_const(list([baseFunc, base_block]), list([tarFunc, target_block]) \
                                                             , s_hash_dict[s_name]["constant"], t_hash_dict[t_name]["constant"])
                                const_matched_bb_dic[baseFunc].update({base_block: {tarFunc + "-" + target_block: const_sim}})
                                count = count + 1
            matched_info_dic.update({baseFunc: {tarFunc: count}})
            del count
            if not const_matched_bb_dic[baseFunc]:
                del const_matched_bb_dic[baseFunc]

        func_sim_info = self.get_function_similarity(count_dict, matched_info_dic, priority_dic)

        return dict({s_name: s_hash_dict[s_name]['bbh']}), dict({t_name: t_hash_dict[t_name]['bbh']}), const_matched_bb_dic, func_sim_info

    def compare_bb_const(self, stand_list, target_list, s_hash_dict, t_hash_dict):

        s_fname, s_sAddr = stand_list
        t_fname, t_sAddr = target_list
        s_const_set = s_hash_dict[s_fname][s_sAddr]
        t_const_set = t_hash_dict[t_fname][t_sAddr]
        s_comp_set = copy.deepcopy(s_const_set)
        t_comp_set = copy.deepcopy(t_const_set)
        matched = 0
        # total_len = 0

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

            #if (matched / total_len) < 1.0:
                #print(f"[debug] unmatched constants :: {s_hash_dict[s_fname][s_sAddr]} --- {t_hash_dict[t_fname][t_sAddr]}")
                #print(f"ㄴ[debug] constants find diff :: {s_comp_set} --- {t_comp_set}")
                #print(f" ")

        return (matched / total_len)

    def get_match_func_level(self, _dict, sim_dict):

        bb_count = 0
        func_match_dic = dict()

        for func, val_01 in _dict.items():
            bb_count = len(list(val_01.keys()))
            temp_dict = dict()
            block_match = dict()
            for s_sAddr, val_02 in val_01.items():
                for match_info, const_sim in val_02.items():
                    target_func, target_block = match_info.split('-')
                    temp_dict[target_block] = target_func
                    block_match[target_block] = (s_sAddr, const_sim)
            temp_result = list(set(temp_dict.values()))

            if len(temp_result) > 1:
                temp = 0
                vote_func = None
                for i in temp_result:
                    cnt = sum(1 for value in temp_dict.values() if value == i)
                    if temp < cnt:
                        temp = cnt
                        vote_func = i
                for target_b, target_f in temp_dict.items():
                    if target_f != vote_func:
                        del block_match[target_b]

                # print(f'{func} -> matched -> {vote_func}')
                # print(f' ㄴ[debug] {temp} vote -> -> {vote_func}')
                # print(f"[DEBUG] if {sim_dict[func][vote_func]}")

                func_match_dic.update({func: [vote_func, block_match, sim_dict[func][vote_func]]})

            else:
                # print(f'{func} -> matched -> {temp_result[0]}')
                # print(f"[DEBUG] else {sim_dict[func][temp_result[0]]}")
                try:
                    func_match_dic.update({func: [temp_result[0], block_match, sim_dict[func][temp_result[0]]]})
                except Exception as e:
                    pass

        return func_match_dic

    def get_const_similarity(self, _dict):
        # st = timeit.default_timer()  # start time

        total_sim = 0
        total_count = 0

        for w, x in _dict.items():
            for y, z in x.items():
                total_sim += (list(z.values())[0])
                total_count += 1

        return (total_sim / total_count)

    def analyze_bbh(self, s_flow_data, t_flow_data):
        '''
        basic block hash(함수 대표값)을 비교해서 점수에 가중치를 매겨 반환하는 함수
        '''

        s_cmp_dic, whitelist_matched_dic1, s_flow_const_dict, = self.parser_bbh(s_flow_data)
        t_cmp_dic, whitelist_matched_dic2, t_flow_const_dict, = self.parser_bbh(t_flow_data)

        flow_const_dict = dict()
        flow_const_dict.update({"base": s_flow_const_dict})
        flow_const_dict.update({"target": t_flow_const_dict})

        cmp_s, cmp_t, true_bb_const_sim, func_sim = self.compare_bbh(s_cmp_dic, t_cmp_dic, flow_const_dict)

        #c_score = self.compare_prime(self.parser_bbh_T_F(cmp_s, ), self.parser_bbh_T_F(cmp_t, ), s_flow_data, t_flow_data)

        func_match_dict = self.get_match_func_level(true_bb_const_sim, func_sim)
        base_F_set = self.parser_bbh_T_F(cmp_s, False)
        target_F_set = self.parser_bbh_T_F(cmp_t, False)
        base_name = list(s_cmp_dic.keys())[0]
        target_name = list(t_cmp_dic.keys())[0]
        find_similar_dic = dict()

        matched_list = list(func_match_dict.keys())
        for i in list(func_match_dict.values()):
            matched_list.append(i)

        for base_F_func in base_F_set[base_name]:
            if base_F_func in matched_list:
                target_F_func = func_match_dict[base_F_func][0]
                for base_F_block in base_F_set[base_name][base_F_func]:
                    base_opcodes = "".join(s_flow_data['func_name'][base_F_func][base_F_block]['opcodes'])
                    if target_F_func in target_F_set[target_name]:
                        for target_F_block in target_F_set[target_name][target_F_func]:
                            target_opcodes = "".join(t_flow_data['func_name'][target_F_func][target_F_block]['opcodes'])
                            sim = NGram.compare(base_opcodes, target_opcodes, N=2)
                            if sim > 0.75:  # opcodes similar over 75%
                                const_sim = self.compare_bb_const(list([base_F_func, base_F_block]), list([target_F_func, target_F_block]),\
                                                                  s_cmp_dic[base_name]['constant'], t_cmp_dic[target_name]['constant'])
                                if const_sim > 0.7:
                                    find_similar_dic.update({base_F_func + '-' + base_F_block: target_F_func + '-' + target_F_block})

        func_match_dict.update({'similar' : find_similar_dic})

        return algo.get_bbh_similarity(cmp_s, ), func_match_dict, whitelist_matched_dic1, true_bb_const_sim

    def analyze_constant(self, standard, target, true_bb_const_sim):
        const_score = list()
        const_score.append(self.get_const_similarity(true_bb_const_sim))
        const_score.append(self.get_all_const_similer(standard['constant'],target['constant']))

        return const_score

    def parser_all_constants(self, _list):
        temp_list = list()
        for i in _list:
            for temp in i.split(" "):
                temp_list.append(temp)

        temp_dic = dict()
        for i in temp_list:
            if i in temp_dic:
                temp_dic[i] = temp_dic[i] + 1
            else:
                temp_dic.update({i: 1})

        return temp_dic

    def get_all_const_similer(self,_base, _target):
        base_const = self.parser_all_constants(_base)
        target_const = self.parser_all_constants(_target)
        const_total_count = len(base_const) + len(target_const)

        diff_dic = dict()
        for base in base_const:
            if base in target_const:
                if base_const[base] < target_const[base]:
                    diff_count = target_const[base] - base_const[base]
                    if diff_count != 0:
                        diff_dic.update({base: diff_count})
                elif base_const[base] > target_const[base]:
                    diff_count = base_const[base] - target_const[base]
                    if diff_count != 0:
                        diff_dic.update({base: diff_count})
                elif base_const[base] == target_const[base]:
                    pass
        const_diff_count = len(diff_dic)

        return ((const_total_count - const_diff_count) / const_total_count)

    def compare_prime(self, base, target, base_idb, target_idb):
        s_cm_dic, whitelist_dic1 = self.parser_bbh(base_idb)
        t_cm_dic, whitelist_dic2 = self.parser_bbh(target_idb)
        s_name = list(base.keys())[0]
        t_name = list(target.keys())[0]
        # diffing
        f_score_list = list()
        for s_value in base.values():
            for s_fname, s_fdata in s_value.items():  # 기준 함수 선택
                for t_value in target.values():
                    for t_fname, t_fdata in t_value.items():  # 대상 함수 선택
                        for s_addr in s_fdata.keys():  # 기준 함수의 베이직 블록 선택
                            for t_addr in t_fdata.keys():  # 대상 함수의 베이직 블록 선택
                                s_prime = base_idb['func_name'][s_fname][s_addr]['block_prime']
                                t_prime = target_idb['func_name'][t_fname][t_addr]['block_prime']

                                ''' 소수 분해하고 나누는 과정'''
                                # 기준과 대상의 소수를 소인수 분해하여 opcode 딕셔너리와 총 갯수로 나눔
                                s_opcodes, s_opcnt = self.factorization(s_prime)
                                t_opcodes, t_opcnt = self.factorization(t_prime)
                                # 나누기를 통해서 기준(분모), 대상(분자)가 가지는 서로 다른 opcode를 찾는다
                                bunmo = Fraction(t_prime, s_prime).denominator
                                bunja = Fraction(t_prime, s_prime).numerator
                                t_diff, t_diffcnt = self.factorization(bunja)
                                s_diff, s_diffcnt = self.factorization(bunmo)
                                # 전체 opcode 개수중에 같은 것의 갯수를 점수로 환산
                                score = (s_opcnt - s_diffcnt + t_opcnt - t_diffcnt) / (s_opcnt + t_opcnt) * 100
                                # 기준과 대상에 대해서 유사도 점수를 저장
                                f_score_list.append((score, s_fname, s_addr, t_fname, t_addr))

        ''' 유사도가 저장된 리스트 정제하는 과정 '''
        # 비었으면 0 반환
        if len(f_score_list) == 0:
            return 0
        # 유사도 순으로 정렬
        f_score_list.sort(reverse=True)
        # 블럭을 1:1 매칭시키기위해서 중복되는 블럭을 제거
        for a in range(len(f_score_list)):
            rmvcnt = 0
            for b in range(a + 1, len(f_score_list)):
                if f_score_list[a][2] == f_score_list[b - rmvcnt][2] or f_score_list[a][4] == f_score_list[b - rmvcnt][4]:
                    f_score_list.remove(f_score_list[b - rmvcnt])
                    rmvcnt += 1
        # 정제가 끝난 리스트에서 유사도가 80%이상인 것만 세서 반환
        s_list = list()
        t_list = list()
        cnt = 0
        for f_score in f_score_list:
            const_score = self.compare_bb_const(list((f_score[1], f_score[2])), list((f_score[3], f_score[4])),
                                                    s_cm_dic[s_name]['constant'], t_cm_dic[t_name]['constant'])
            if (f_score[0] > 80) and (const_score > 0):
                cnt += 1
                #print(f_score, const_score)
        return cnt

    def factorization(self, num):
        # 전체 opcode 갯수 중에서 mod 연산했을 시 0이 나오는 것을 세어 유사도 점수를 측정
        opdict = dict()
        full_count = 0
        for opcode, prime in const_filter_indexs.prime_set.items():
            count = 0
            while num % prime == 0:
                num //= prime
                count += 1
            if count > 0:
                opdict[opcode] = count
                full_count += count
            if num == 1:
                break
        return opdict, full_count

    def analyze_all(self):

        idb_all = OrderedDict()
        idb_func_all = dict()

        for index_1, idb_info_s in enumerate(self.idb_list):
            idb_s = dict()
            idb_func_s = dict()
            yun_s = dict()
            for index_2, idb_info_t in enumerate(self.idb_list):
                idb_t = dict()
                if index_1 == index_2:
                    continue

                idb_t['bbh'], idb_func_s[idb_info_t['file_name']], idb_func_s['whitelist'], true_bb_const_sim = self.analyze_bbh(idb_info_s, idb_info_t)
                idb_t['const_value'] = self.analyze_constant(idb_info_s, idb_info_t, true_bb_const_sim)

                idb_s[idb_info_t['file_name']] = idb_t

            idb_all[idb_info_s['file_name']] = idb_s
            idb_func_all[idb_info_s['file_name']] = idb_func_s

            with open(r"C:\malware\all_result\cfg" + "\\" + "result_cfg.txt", 'w') as makefile:
                json.dump(idb_func_all, makefile, ensure_ascii=False, indent='\t')

        return idb_all