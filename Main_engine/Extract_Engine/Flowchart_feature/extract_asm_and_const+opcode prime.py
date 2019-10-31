import json
import timeit
import idb
import hashlib
from Main_engine.Extract_Engine.Flowchart_feature import const_filter_indexs
from fractions import Fraction


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
    return opdict, full_count

def diff_prime_set(target, standard):
    target_dict = dict()
    standard_dict = dict()
    score_list = list()
    result_score = 0

    for a in target['func_name']:
        for b in target['func_name'][a]:
            if b != 'flow_opString':
                target_dict[b] = target['func_name'][a][b]['block_prime'], False

    for a in standard['func_name']:
        for b in standard['func_name'][a]:
            if b != 'flow_opString':
                standard_dict[b] = standard['func_name'][a][b]['block_prime'], False

    # diffing
    for t_addr, t_prime in target_dict.items():
        for s_addr, s_prime in standard_dict.items():
            if s_prime[1]:
                # print(f"[debug] Target {dd} is already selected! {cnt1}")
                continue

            gijun, gijun_cnt = factorization(t_prime[0])
            deasang, deasang_cnt = factorization(s_prime[0])
            bunmo = Fraction(t_prime[0], s_prime[0]).denominator
            bunja = Fraction(t_prime[0], s_prime[0]).numerator
            diff_gijun, diff_gijun_cnt = factorization(bunja)
            diff_deasang, diff_deasang_cnt = factorization(bunmo)
            diff_gijun_score = (gijun_cnt - diff_gijun_cnt) / gijun_cnt
            diff_deasang_score = (deasang_cnt - diff_deasang_cnt)/deasang_cnt

            print(f"[diff] Diffing between {t_addr} and {s_addr}")
            print(f"대상블록({t_addr})")
            print(f" o 유사도 : {gijun_cnt - diff_gijun_cnt}/{gijun_cnt} = {diff_gijun_score}")
            print(f" o 다른 부분 :{diff_gijun}")
            print(f"기준블록({s_addr})")
            print(f" o 유사도 : {deasang_cnt - diff_deasang_cnt}/{deasang_cnt} = {diff_deasang_score}")
            print(f" o 다른 부분diff :{diff_deasang}\n")

            score_list.append((diff_gijun_score, t_addr, s_addr))
            # 두개가 완전히 같으면 둘 다 제외
            if diff_gijun_score == 1:
                target_dict[t_addr] = 0, True
                standard_dict[s_addr] = 0, True

    # 리스트를 유사도 순으로 정렬
    score_list.sort(reverse=True)

    # 유사도 순으로 남기고 지움
    # print(range(len(score_list)))
    for a in range(len(score_list)):
        rmvcnt = 0
        for b in range(a+1, len(score_list)):
             if score_list[a][1] == score_list[b-rmvcnt][1] or score_list[a][2] == score_list[b-rmvcnt][2]:
                score_list.remove(score_list[b-rmvcnt])
                rmvcnt += 1
    for score in score_list:
        result_score += score[0]
    result_score /= len(score_list)
    print(f"[debug] 총점 : {result_score}")
    print(f"[debug] 대상 블록 수 : {len(target_dict)}")
    print(f"[debug] 기준 블록 수 : {len(standard_dict)}")
    print(f"[debug] Total score : {result_score}")


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
    diff_prime_set(arg1, arg2)
    # print(f"[except]Not found opcodes : {except_list}")
    print(f"[+]running : {timeit.default_timer() - s}")  # end time
    print("-----END-----")
