import json
import timeit
import idb
import hashlib
from Main_engine.Extract_Engine.Flowchart_feature import const_filter_indexs

glo_list = list()  # PE 전체의 constant 값을 담을 global list


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

                # 베이직 블록 내 어셈블리어 추출
                while curaddr < endaddr:
                    opcode = self.api.idc.GetMnem(curaddr)
                    disasm = self.api.idc.GetDisasm(curaddr)

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
<<<<<<< HEAD
                                if operand[0] != '0':
=======
                                if operand[0] != '0' and len(operand[0]) != 8:  # 8length 일단 하드코딩, 정규식으로 교채해야함
>>>>>>> upstream/master
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


if __name__ == "__main__":
    s = timeit.default_timer()  # start time
    PATH = r"C:\malware\mid_idb\test_ (12).idb"
    idb_sub_function_info = basicblock_idb_info_extraction(PATH)

    with open(r"C:\malware\result\test.txt", 'w') as makefile:
        json.dump(idb_sub_function_info, makefile, ensure_ascii=False, indent='\t')

    print(f"[+]running : {timeit.default_timer() - s}")  # end time
    print("-----END-----")