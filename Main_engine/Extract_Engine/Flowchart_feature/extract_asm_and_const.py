import json
import signal
import timeit
import idb
import hashlib

import pefile
from Main_engine.Extract_Engine.Flowchart_feature import const_filter_indexs

glo_constant = list()  # PE 전체의 constant 값을 담을 global list
except_list = set() # 없는 opcode 저장용

class idb_info(object):
    def __init__(self, api, fva):
        self.api = api
        self.fva = fva
        self.function = self.api.ida_funcs.get_func(self.fva)
        self.MinEA = hex(self.api.idc.MinEA())
        self.MaxEA = hex(self.api.idc.MaxEA())
        self.MinEA_int = int(self.MinEA, 16)
        self.MaxEA_int = int(self.MaxEA, 16)

class basic_block(idb_info):
    def __init__(self, api, fva, func_name):
        super(basic_block, self).__init__(api, fva)
        self.func_name = func_name

    def bbs(self, func_name_dicts, file_name):
        # mutex_opcode_list = list()
        flow_opcode = list()
        flow_constants = list()
        function_dicts = dict()
        idb_info = dict()
        func_name_dicts[self.func_name] = dict()
        flow_branch = list()

        # 함수 내에서 플로우 차트 추출
        try:
            function_flowchart = self.api.idaapi.FlowChart(self.function)
            # 플로우 차트에서 반복문 돌려 각 베이직 블록 추출
        except:
            print('can not parsing flowchart!!!')
            return

        for basicblock in function_flowchart:
            try:
                curaddr = basicblock.startEA
                endaddr = basicblock.endEA

                # 30bytes 이하 블럭 필터 비활성화
                # if (endaddr - curaddr) < 30:  # 최소 바이트 50이상 할것
                #     continue

                opcodes = list()
                hex_opcodes = list()
                disasms = list()
                block_constant = list()  # block 단위의 상수 (ascii string 뽑기)
                function_dicts[hex(curaddr)] = dict()
                basic_block_prime = 1
                prime_dict = dict()

                ''' 베이직 블로 브랜치 추출 '''
                for succ in basicblock.succs():
                    flow_branch.append((hex(curaddr), hex(succ.startEA)))

                # 베이직 블록 내 어셈블리어 추출
                while curaddr < endaddr:
                    opcode = self.api.idc.GetMnem(curaddr)
                    disasm = self.api.idc.GetDisasm(curaddr)

                    ''' opcode_prime 추출(임시명 BBP(basic block prime) '''
                    if opcode in const_filter_indexs.prime_set.keys():
                        basic_block_prime *= const_filter_indexs.prime_set[opcode]
                        opcode_prime = const_filter_indexs.prime_set[opcode]  # opcode에 해당하는 소수
                        # 이미 있는 opcode면 +1해주고 없으면 0으로 세팅해서 +1
                        prime_dict[opcode_prime] = prime_dict[opcode_prime] + 1 if opcode_prime in prime_dict else 1
                        ''' 요기 예외 처리 로직 넣어야함'''
                    else:
                        except_list.add(opcode)

                    '''--- 상수값 추출 시작 ---'''
                    if opcode in const_filter_indexs.indexs:  # instruction white list
                        operand = self.api.idc._disassemble(curaddr).op_str.split(',')
                        if len(operand) == 2:  # operand가 2개일 때 조건입장
                            unpack_1, unpack_2 = operand  # unpacking list
                            operand_1 = unpack_1.strip()  # 공백제거
                            operand_2 = unpack_2.strip()

                            if operand_1 not in const_filter_indexs.pointer:  # esp, esi, ebp가 아니여야 입장
                                if "ptr" not in operand_2 and operand_2 not in const_filter_indexs.logic:
                                    if operand_2 not in const_filter_indexs.registers and "[" not in operand_2 and "]" not in operand_2:
                                        if operand_2.find('0x') != -1 and self.MinEA_int <= int(operand_2, 16) and int(operand_2, 16) <= self.MaxEA_int:
                                            pass
                                        else:
                                            glo_constant.append(operand_2)  # append file total constant
                                            block_constant.append(operand_2)  # append block constant

                        elif operand[0] != "": # 0주소 명령일 때 공백필터
                            if operand[0] not in const_filter_indexs.registers and "ptr" not in operand[0] and operand[0] not in const_filter_indexs.logic:
                                if operand[0].find('0x') != -1 and self.MinEA_int <= int(operand[0], 16) and int(operand[0], 16) <= self.MaxEA_int:
                                    pass
                                else:
                                    glo_constant.append(operand[0])  # append file total constant
                                    block_constant.append(operand[0])  # append block constant

                        else:   # 3주소 pass
                            pass
                    '''--- 상수값 추출 끝 ---'''
                    # 3주소 명령도 있음? 그러면 위에 else로 빠져서 쓸모없는 값 뽑을 수 있음....
                    opcodes.append(opcode)
                    hex_opcodes.append(int(opcode.encode("utf-8").hex(), 16))
                    disasms.append(disasm)
                    curaddr = self.api.idc.NextHead(curaddr)
                ''' ================================ END ONE BLOCK ================================'''
                # 중복 값 제어 비활성화
                # mutex_opcode = ' '.join(opcodes)  # mutex_opcode -> type(str)
                # if mutex_opcode in mutex_opcode_list:
                #     del function_dicts[hex(basicblock.startEA)]  # del 안하면 비어있는 딕셔너리 생김 ex) 0x402034 = {}
                #     continue
                # else:
                #     mutex_opcode_list.append(mutex_opcode)

                basicblock_dics = {
                    'opcodes': opcodes,
                    'disasms': disasms,
                    'block_sha256': hashlib.sha256(hex(sum(hex_opcodes)).encode()).hexdigest(),  # add my codes
                    'start_address': hex(basicblock.startEA),
                    'end_address': hex(basicblock.endEA),
                    'block_constant': ' '.join(block_constant),
                    'block_prime': basic_block_prime,
                    'prime_dict': prime_dict,
                }
                #flow_opcode.append(mutex_opcode)
                function_dicts[hex(basicblock.startEA)] = basicblock_dics
                if block_constant:
                    flow_constants.append(' '.join(block_constant))
            except:
                continue
        ''' ================================ END ONE Flowchart ================================'''

        func_name_dicts[self.func_name] = function_dicts

        if len(func_name_dicts[self.func_name]) == 0:
            del func_name_dicts[self.func_name]  # del 안하면 비어있는 딕셔너리 생김
        else:
            func_name_dicts[self.func_name].update({'flow_opString': ' '.join(flow_opcode)})
            # flow_opString 붙이는 부분에서 상수 strings도 붙여야 함수단위 상수셋팅 가능
            func_name_dicts[self.func_name].update({'flow_constants': ' '.join(flow_constants)})
            func_name_dicts[self.func_name].update({'flow_branches': flow_branch})

        idb_info['file_name'] = file_name
        idb_info['func_name'] = func_name_dicts

        return idb_info

def main(api, file_name):
    function_dicts = dict()
    func_name = list()
    func_branch = list()
    cg_dict = dict()
    for fva in api.idautils.Functions():
        # 함수이름 출력

        fname = api.idc.GetFunctionName(fva).lower()

        if 'dllentry' in fname or fname[:3] == 'sub' or fname[:5] == 'start' or fname.find('main') != -1:
            func_name.append(fname)
            for addr in api.idautils.XrefsTo(fva, 0):
                # print(hex(addr.src), hex(addr.dst), addr.type)
                try:
                    if addr.type is 17:
                        # print(api.ida_funcs.get_func_name(api.ida_funcs.get_func(addr.src).startEA))
                        # print(f"\x1b[1;32mT : From {(api.idc.GetFunctionName(addr.src))}({hex(addr.src)}) To {fname}\x1b[1;m")
                        func_branch.append(
                            (api.ida_funcs.get_func_name(api.ida_funcs.get_func(addr.src).startEA), fname))
                except:
                #     print(f"F : From {dir(addr)}")
                    pass

            # main or start or sub_***** function. not library function
            basicblock = basic_block(api, fva, fname)

            # 베이직 블록 정보 추출 함수 실행
            basicblock_function_dicts = basicblock.bbs(function_dicts, file_name)

    # func_name = set(func_name)
    cg_dict['f_name'] = func_name
    cg_dict['f_branch'] = func_branch


    with open(r'C:\malware\all_result\cg' + "\\" + file_name + '.txt', 'w') as file:
        json.dump(cg_dict, file, ensure_ascii=False, indent='\t')

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
    idb_sub_function_info.update({'constant': ' '.join(glo_constant)})
    # END

    return idb_sub_function_info


if __name__ == "__main__":

    s = timeit.default_timer()  # start time
    PATH = r"D:\Project\PL자료\malware\Andariel\0e122fc1dc0bd63c4474508c654e42e9813a9f6e0857aca8ed18619707f8dd0c.idb"
    idb_sub_function_info = basicblock_idb_info_extraction(PATH)
    #
    # with open(r"C:\Users\qkrwl\Documents\카카오톡 받은 파일\Anda\test.txt", 'w') as makefile:
    #     json.dump(idb_sub_function_info, makefile, ensure_ascii=False, indent='\t')
    #
    # print(f"[+]running : {timeit.default_timer() - s}")  # end time
    # print("-----END-----")