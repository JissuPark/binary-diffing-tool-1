import json
import timeit
import idb
import hashlib
from Main_engine.Extract_Engine.Flowchart_feature import const_filter_indexs
from fractions import Fraction
from pprint import pprint

glo_list = list()  # PE 전체의 constant 값을 담을 global list
except_list = set() # 없는 opcode 저장용ㄴ


class idb_info(object):
    def __init__(self, api, fva):
        self.api = api
        self.fva = fva
        self.function = self.api.ida_funcs.get_func(self.fva)


class basic_block(idb_info):

    def __init__(self, api, fva, func_name):
        super(basic_block, self).__init__(api, fva)
        self.func_name = func_name

    def bbs(self, func_name_dicts, file_name):
        mutex_opcode_list = []
        opcode_flow = []
        function_dicts = {}
        idb_info = {}
        func_name_dicts[self.func_name] = {}
        # 함수 내에서 플로우 차트 추출
        function_flowchart = self.api.idaapi.FlowChart(self.function)

        # 플로우 차트에서 반복문 돌려 각 베이직 블록 추출
        try:
            for basicblock in function_flowchart:
                curaddr = basicblock.startEA
                endaddr = basicblock.endEA

                if (endaddr - curaddr) < 30:  # 최소 바이트 50이상 할것
                    continue

                opcodes = []
                hex_opcodes = []
                disasms = []
                block_constant = []  # block 단위의 상수 (ascii string 뽑기)
                function_dicts[hex(curaddr)] = {}
                basic_block_prime = 1
                prime_dict = dict()

                # 베이직 블록 내 어셈블리어 추출
                while curaddr < endaddr:
                    opcode = self.api.idc.GetMnem(curaddr)
                    disasm = self.api.idc.GetDisasm(curaddr)

                    ''' opcode_prime 추출(임시면 BBP(basic block prime) '''
                    if opcode in const_filter_indexs.prime_set.keys():
                        basic_block_prime *= const_filter_indexs.prime_set[opcode]
                        opcode_prime = const_filter_indexs.prime_set[opcode]    # opcode에 해당하는 소수
                        # 이미 있는 opcode면 +1해주고 없으면 0으로 세팅해서 +1
                        prime_dict[opcode_prime] = prime_dict[opcode_prime]+1 if opcode_prime in prime_dict else 1
                        ''' 요기 예외 처리 로직 넣어야함'''
                    else:
                        except_list.add(opcode)
                    ######################################################
                    # Comprehension 이전 버전임                            #
                    # if opcode_prime in basic_block_prime:              #
                    #     prime_count = basic_block_prime[opcode_prime]  #
                    # else:                                              #
                    #     prime_count = 0                                #
                    # basic_block_prime[opcode_prime] = prime_count+1    #
                    ######################################################

                    '''--- 상수값 추출 시작 ---'''
                    if opcode in const_filter_indexs.indexs:  # instruction white list
                        operand = self.api.idc._disassemble(curaddr).op_str.split(',')
                        if len(operand) == 2:  # operand가 2개일 때 조건입장
                            unpack_1, unpack_2 = operand  # unpacking list
                            operand_1 = unpack_1.strip()  # 공백제거
                            operand_2 = unpack_2.strip()
                            # print(f'01 ::: {operand_1}, 02::: {operand_2}') # 테스트코드
                            if operand_1 not in const_filter_indexs.pointer:  # esp, esi, ebp가 아니여야 입장
                                if "ptr" not in operand_2 and operand_2 not in const_filter_indexs.logic:  # ptr, 0xffffffff 등 없어야 입장
                                    if operand_2 not in const_filter_indexs.registers:  # 레지스터가 없어야 입장
                                        if operand_2 != '0' and len(operand_2) != 8 and "[" not in operand_2 and "]" not in operand_2:
                                            glo_list.append(operand_2)  # append file total constant
                                            block_constant.append(operand_2)  # append block constant
                        else:  # operand가 1개일 때 조건입장
                            if operand[0] not in const_filter_indexs.registers and "ptr" not in operand[0] and operand[0] not in const_filter_indexs.logic:  # 레지가아니고 ptr도 없어야 입장
                                if operand[0] != '0' and len(operand[0]) != 8:  # 8length 일단 하드코딩, 정규식으로 교채해야함
                                    glo_list.append(operand[0])
                                    block_constant.append(operand[0])
                    '''--- 상수값 추출 끝 ---'''
                    # 3주소 명령도 있음? 그러면 위에 else로 빠져서 쓸모없는 값 뽑을 수 있음....
                    opcodes.append(opcode)
                    hex_opcodes.append(int(opcode.encode("utf-8").hex(), 16))
                    disasms.append(disasm)
                    curaddr = self.api.idc.NextHead(curaddr)
                ''' ================================ END ONE BLOCK ================================'''
                # 중복 값 제어
                mutex_opcode = ' '.join(opcodes)  # mutex_opcode -> type(str)
                if mutex_opcode in mutex_opcode_list:
                    del function_dicts[hex(basicblock.startEA)]  # del 안하면 비어있는 딕셔너리 생김 ex) 0x402034 = {}
                    continue
                else:
                    mutex_opcode_list.append(mutex_opcode)

                basicblock_dics = {
                    'opcodes': opcodes,
                    'disasms': disasms,
                    'block_sha256': hashlib.sha256(hex(sum(hex_opcodes)).encode()).hexdigest(),  # add my codes
                    'block_prime' : basic_block_prime,
                    'prime_dict': prime_dict,
                    'start_address': hex(basicblock.startEA),
                    'end_address': hex(basicblock.endEA),
                    'block_constant': ' '.join(block_constant)
                }
                opcode_flow.append(mutex_opcode)
                function_dicts[hex(basicblock.startEA)] = basicblock_dics
                #function_name['funct_name'] = function_dicts
        except:
            print('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
        ''' ================================ END ONE Flowchart ================================'''
        func_name_dicts[self.func_name] = function_dicts

        if len(func_name_dicts[self.func_name]) == 0:
            del func_name_dicts[self.func_name]  # del 안하면 비어있는 딕셔너리 생김
        else:
            func_name_dicts[self.func_name].update({'flow_opString': ' '.join(opcode_flow)})

        idb_info['file_name'] = file_name
        idb_info['func_name'] = func_name_dicts
        #idb_info['func_name'] = func_name_dicts
        #idb_info['func_name'] = func_name_dicts


        # del(opcodes)
        # del(hex_opcodes)
        # del(disasms)
        # del(block_constant)
        # del(function_dicts)
        # del(mutex_opcode_list)
        # del(opcode_flow)
        # del(function_dicts)
        # del(func_name_dicts)

        return idb_info


def main(api, file_name):
    function_dicts = {}

    for fva in api.idautils.Functions():
        # 함수이름 출력
        fname = api.idc.GetFunctionName(fva).lower()
        if 'dllentry' in fname or fname[:3] == 'sub' or fname[:5] == 'start' or fname.find('main') != -1:
            # main or start or sub_***** function. not library function
            basicblock = basic_block(api, fva, fname)
            # 베이직 블록 정보 추출 함수 실행
            basicblock_function_dicts = basicblock.bbs(function_dicts, file_name)

    return basicblock_function_dicts


def open_idb(FROM_FILE):
    with idb.from_file(FROM_FILE) as db:
        api = idb.IDAPython(db)
        print(api)
        return api


def basicblock_idb_info_extraction(FROM_FILE):

    api = open_idb(FROM_FILE)
    idb_sub_function_info = main(api, FROM_FILE[(FROM_FILE.rfind('\\'))+1:-4])
    # 여기서 상수값 붙임. json 맨 아래에 통쨰로 붙이기 위함.
    idb_sub_function_info.update({'constant': ' '.join(glo_list)})
    # END

    return idb_sub_function_info


def factorization(num):
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


def dict_parse(json_data):
    '''
    입력으로 들어온 json 형식의 데이터를 파싱해서
    {함수 이름 : {시작 주소1: (basic block prime, false),
                시작 주소2: (basic block prime, false),
                            ...                      }
    }
    위와 같은 형태로 저장해주는 함수
    :param json_data: 추출엔진에서 나오는 데이터
    :return: 소수를 비교하기위해 정리된 dictionary 형태의 데이터
    '''
    data_dict = dict()
    for func_name in json_data['func_name']:
        func_dict = dict()
        for bb_addr in json_data['func_name'][func_name]:
            if bb_addr != 'flow_opString':
                func_dict[bb_addr] = [json_data['func_name'][func_name][bb_addr]['block_prime'], False]
        data_dict[func_name] = func_dict
    # print(json.dumps(data_dict, indent=4))
    return data_dict


def diff_prime_set(standard, target):
    target_dict = dict()
    standard_dict = dict()

    # json parsing
    target_dict = dict_parse(target)
    standard_dict = dict_parse(standard)


    # diffing
    f_score_list = list()
    for s_fname, s_fdata in standard_dict.items(): # 기준 함수 선택
        for t_fname, t_fdata in target_dict.items(): # 대상 함수 선택
            bb_score_list = list()
            for s_addr, s_prime in s_fdata.items(): # 기준 함수의 베이직 블록 선택
                for t_addr, t_prime in t_fdata.items(): # 대상 함수의 베이직 블록 선택
                    # 이미 검사한 부분(True로 설정)은 넘어감
                    # if t_prime[1]:
                    #     # print(f"[debug] Target {t_addr} is already selected! ")
                    #     continue

                    s_opcodes, s_opcnt = factorization(s_prime[0])
                    t_opcodes, t_opcnt = factorization(t_prime[0])
                    bunmo = Fraction(t_prime[0], s_prime[0]).denominator
                    bunja = Fraction(t_prime[0], s_prime[0]).numerator
                    t_diff, t_diffcnt = factorization(bunja)
                    s_diff, s_diffcnt = factorization(bunmo)
                    s_score = (s_opcnt - s_diffcnt) / s_opcnt
                    t_score = (t_opcnt - t_diffcnt) / t_opcnt

                    # print(f"[diff] Diffing between {t_addr} and {s_addr}")
                    # print(f"기준블록({t_addr})")
                    # print(f" o 유사도 : {s_opcnt - s_diffcnt}/{s_opcnt} = {s_score}")
                    # print(f" o 다른 부분 :{s_diff}")
                    # print(f"대상블록({s_addr})")
                    # print(f" o 유사도 : {t_opcnt - t_diffcnt}/{t_opcnt} = {t_score}")
                    # print(f" o 다른 부분diff :{t_diff}\n")

                    bb_score_list.append((s_score, s_addr, t_addr))
                    # 두개가 완전히 같으면 둘 다 제외
                    if s_score == 1:
                        target_dict[t_fname][t_addr][1] = True
                        standard_dict[s_fname][s_addr][1] = True
            if len(bb_score_list) == 0:
                continue
            print(f"\x1b[1;34m{bb_score_list}\x1b[1;m")
            # 리스트를 유사도 순으로 정렬
            bb_score_list.sort(reverse=True)

            # 유사도 순으로 남기고 지움
            # print(range(len(score_list)))
            for a in range(len(bb_score_list)):
                rmvcnt = 0
                for b in range(a+1, len(bb_score_list)):
                     if bb_score_list[a][1] == bb_score_list[b-rmvcnt][1] or bb_score_list[a][2] == bb_score_list[b-rmvcnt][2]:
                        bb_score_list.remove(bb_score_list[b-rmvcnt])
                        rmvcnt += 1
            print(f"\x1b[1;32m{bb_score_list}\x1b[1;m")
            bb_result_score = 0
            for bb_score in bb_score_list:
                bb_result_score += bb_score[0]
            print(f"[diff] Diffing between {s_fname} and {t_fname}")
            print(f"[debug] 함수 총점 : {bb_result_score}/{len(bb_score_list)}")
            bb_result_score /= len(s_fdata)
            print(f"[debug] {t_fname} 대상 블록 수 : {len(t_fdata)}")
            print(f"[debug] {s_fname} 기준 블록 수 : {len(s_fdata)}")
            print(f"[debug] 함수 score : {bb_result_score}")
            f_score_list.append((bb_result_score, s_fname, t_fname, bb_score_list))
            print(f"\x1b[1;31m{f_score_list}\x1b[1;m")

    print(f"\x1b[1;33m{f_score_list}\x1b[1;m")
    f_score_list.sort(reverse=True)
    for a in range(len(f_score_list)):
        rmvcnt = 0
        for b in range(a+1, len(f_score_list)):
            if f_score_list[a][1] == f_score_list[b-rmvcnt][1] or f_score_list[a][2] == f_score_list[b-rmvcnt][2]:
                f_score_list.remove(f_score_list[b-rmvcnt])
                rmvcnt += 1
    print(f"\x1b[1;35m{f_score_list}\x1b[1;m")
    f_result_score = 0
    for f_score in f_score_list:
        f_result_score += f_score[0]
    print(f"[debug] 총점 : {f_result_score}/{len(f_score_list)}")
    f_result_score /= len(standard_dict)
    print(f"[debug] 대상 함수 수 : {len(target_dict)}")
    print(f"[debug] 기준 함수 수 : {len(standard_dict)}")
    print(f"[debug] Total score : {f_result_score}")



if __name__ == "__main__":
    s = timeit.default_timer()  # start time
    # PATH1 = r"C:\malware\mid_idb\41A004EBB42648DCA2AFA78680FD70DFEC9DA8C5190C2CF383A7C668A1C4C38F.idb"
    # idb_sub_function_info1 = basicblock_idb_info_extraction(PATH1)
    # PATH2 = r"C:\malware\mid_idb\49B769536224F160B6087DC866EDF6445531C6136AB76B9D5079CE622B043200.idb"
    # idb_sub_function_info2 = basicblock_idb_info_extraction(PATH2)
    #
    # with open(r"C:\malware\result\test1.txt", 'w') as makefile:
    #     json.dump(idb_sub_function_info1, makefile, ensure_ascii=False, indent='\t')
    # with open(r"C:\malware\result\test2.txt", 'w') as makefile:
    #     json.dump(idb_sub_function_info2, makefile, ensure_ascii=False, indent='\t')

    fd1 = open(r"C:\malware\result\test1.txt", 'rb').read()
    arg1 = json.loads(fd1, encoding='utf-8')
    fd2 = open(r"C:\malware\result\test2.txt", 'rb').read()
    arg2 = json.loads(fd2)

    print(f"[analyze]Analyze Start!")
    # 첫번째로 들어오는게 기준, 두번째가 타겟
    diff_prime_set(arg1, arg2)
    # print(f"[except]Not found opcodes : {except_list}")
    print(f"[+]running : {timeit.default_timer() - s}")  # end time
    print("-----END-----")