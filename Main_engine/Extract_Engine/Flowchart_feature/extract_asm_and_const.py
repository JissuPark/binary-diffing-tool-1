import idb
import timeit
import hashlib
import json

from Main_engine.Extract_Engine.Flowchart_feature import const_filter_indexs as _filter

api = None
filename = None
filetype = None

imageBase = None
glo_MinEA = None
glo_MaxEA = None
glo_Constants = list()

# debug info
except_list = set()
err_log = list()


def extract_basic_block_info(fva, funcName, func_ext_dict, tag):
    global api
    global imageBase
    global glo_MinEA
    global glo_MaxEA
    global glo_Constants
    global filename
    global err_log
    global except_list

    FlowChart_info = api.idaapi.FlowChart(api.ida_funcs.get_func(fva))
    func_ext_dict[funcName] = dict()  # function level dict (key: funcName)
    func_ext_const = list()  # function level extract constants list
    bb_ext_dict = dict()  # block level dict (key: startAddress)
    bb_branch = list()  # fuction in block branch info

    try:
        for BasicBlock in FlowChart_info:

            curaddr = BasicBlock.startEA
            endaddr = BasicBlock.endEA
            opcodes = list()  # block level opcodes
            disasms = list()  # block level operands
            constants = list()  # block level constans
            hex_opcodes = list()  # block level opcodes to convert integer (str->hex->int)
            #bb_ext_dict[hex(BasicBlock.startEA)] = dict()  # block level extract info dict
            basic_block_prime = 1

            '''--- Extract fuction in Basic block Branch info ---'''
            for succ in BasicBlock.succs():
                bb_branch.append((hex(curaddr), hex(succ.startEA)))

            while curaddr < endaddr:
                # opcode = api.idc.GetMnem(curaddr) # disable code (overload call)
                disasm = api.idc.GetDisasm(curaddr)
                cutNumber = disasm.find('\t')
                opcode = disasm[:cutNumber]  # block level 1 line opcode
                operand = disasm[cutNumber:].replace('\t', '')  # block level 1 line operand

                '''--- Get Prime ---'''
                if opcode in _filter.prime_set.keys():
                    basic_block_prime *= _filter.prime_set[opcode]
                else:
                    except_list.add(opcode)

                '''--- constant value extraction ---'''
                if operand == "":  # 0-Address Instruction Filter
                    pass
                else:
                    operand = operand.split(',')

                    if len(operand) == 1:  # 1-Address Instruction Filter
                        if operand[0] not in _filter.reg and '[' not in operand[0]:
                            if '0x' in operand[0] and glo_MinEA <= int(operand[0], 16) <= glo_MaxEA:
                                pass
                            elif operand[0] not in imageBase and operand[0] not in _filter.logic:
                                constants.append(operand[0])

                    elif len(operand) == 2:  # 2-Address Instruction Filter
                        operand_1, operand_2 = operand
                        operand_2 = operand_2[1:]

                        if operand_1 not in _filter.pointer:
                            if operand_2 not in _filter.reg and 'ptr' not in operand_2 and '[' not in operand_2:
                                if '0x' in operand_2 and glo_MinEA <= int(operand_2, 16) <= glo_MaxEA:
                                    pass
                                elif operand_2 not in imageBase and operand_2 not in _filter.logic:
                                    constants.append(operand_2)

                    else:  # 3-Address Instruction exception
                        # print(f'[Debug][Sensing] 3-Address Instruction({funcName}-{hex(BasicBlock.startEA)})')
                        operand_1, operand_2, operand_3 = operand
                        operand_2 = operand_2[1:]

                        if operand_1 not in _filter.pointer and operand_2 not in _filter.pointer:

                            if operand_2 not in _filter.reg and 'ptr' not in operand_2 and '[' not in operand_2:
                                if '0x' in operand_2 and glo_MinEA <= int(operand_2, 16) <= glo_MaxEA:
                                    pass
                                elif operand_2 not in imageBase and operand_2 not in _filter.logic:
                                    constants.append(operand_2)

                            if operand_3 not in _filter.reg and 'ptr' not in operand_3 and '[' not in operand_3:
                                if '0x' in operand_3 and glo_MinEA <= int(operand_3, 16) <= glo_MaxEA:
                                    pass
                                elif operand_3 not in imageBase and operand_3 not in _filter.logic:
                                    constants.append(operand_3)
                '''--- END constant value extraction ---'''

                opcodes.append(opcode)
                hex_opcodes.append(int(opcode.encode("utf-8").hex(), 16))
                disasms.append(disasm)
                curaddr = api.idc.NextHead(curaddr)
                del disasm, cutNumber, opcode, operand

            temp = ' '.join(constants)
            basicblock_dic = {
                'opcodes': opcodes,
                'disasms': disasms,
                'block_sha256': hashlib.sha256(hex(sum(hex_opcodes)).encode()).hexdigest(),
                'start_addr': hex(BasicBlock.startEA),
                'end_addr': hex(endaddr),
                'block_constant': temp,
                'block_prime': basic_block_prime,
            }
            if basicblock_dic:
                bb_ext_dict[hex(BasicBlock.startEA)] = basicblock_dic

            if constants:
                func_ext_const.append(temp)
                glo_Constants.append(temp)
                del temp
            del constants, opcodes, disasms, hex_opcodes
    except Exception as e:
        # print(f'[debug] Extract_ {e}')
        err_log.append("Extract_" + str(e))

    bb_ext_dict.update({'flow_constants': func_ext_const})
    bb_ext_dict.update({'flow_branches': bb_branch})

    if bb_ext_dict:
        func_ext_dict[funcName] = bb_ext_dict
    del bb_ext_dict

    tagging = dict()

    if basicblock_dic['block_sha256'] in tag:
        for tag_hash, tag_const in tag.items():
            for tag_group, set in tag_const.items():
                tagging['tagging'] = set
    else:
            tagging['tagging'] = {}

    return tagging

    del basicblock_dic

def main(tag):
    global filename
    global api
    global imageBase
    global glo_MaxEA
    global glo_MinEA
    global err_log
    global glo_Constants
    global err_log
    global except_list

    func_ext_dict = dict()  # functionn level extract info dict
    glo_MaxEA = int(hex(api.idc.MaxEA()), 16)
    glo_MinEA = int(hex(api.idc.MinEA()), 16)
    imageBase = _filter.imageBase
    imageBase.append(str(hex(api.idaapi.get_imagebase())))

    func_branch = list()
    func_name = list()
    cg_info_dict = dict()

    for fva in api.idautils.Functions():
        FuncName = api.idc.GetFunctionName(fva).lower()
        if FuncName[:3] == 'sub' or "start" in FuncName or "main" in FuncName or "dllentry" in FuncName:
            tagging = extract_basic_block_info(fva, FuncName, func_ext_dict, tag)
            func_name.append(FuncName)

            for addr in api.idautils.XrefsTo(fva, 0):
                try:
                    if addr.type is 17:
                        func_branch.append(
                            (api.ida_funcs.get_func_name(api.ida_funcs.get_func(addr.src).startEA), FuncName))
                except Exception as e:
                    err_log.append("XrefsTo_" + str(e))
            del FuncName

    cg_info_dict['f_name'] = func_name
    cg_info_dict['f_branch'] = func_branch

    # saved block flow graph
    with open("C:\\malware\\all_result\\cg\\"+filename+".txt", 'w') as makefile:
        json.dump(cg_info_dict, makefile, ensure_ascii=False, indent='\t')

    del func_name, func_branch, cg_info_dict

    return func_ext_dict, tagging


def basicblock_info_extraction(FROM_FILE, tag):
    global api
    global filetype

    global glo_Constants
    result_dic = dict()
    api = open_idb(FROM_FILE)

    # print(f"[INFO][Extract Binary][MD5]{api.idc.GetInputMD5()}")
    print(f'[INFO][Extract Binary] {filename}')

    func_ext_dict, tagging = main(tag)

    result_dic = ({"file_name": filename, "type" : filetype,"func_name": func_ext_dict, "constant": glo_Constants, "tagging" :tagging['tagging']} )


    return result_dic, tagging


def open_idb(FROM_FILE):
    global filename
    global filetype
    filename = FROM_FILE[FROM_FILE.rfind('\\') + 1:-4]
    filetype = FROM_FILE[-3:]

    with idb.from_file(FROM_FILE) as db:
        api = idb.IDAPython(db)
        return api


if __name__ == "__main__":
    s = timeit.default_timer()  # start time

    PATH = "D:\\out_idb\\Andariel\\a078d038b8b0bbc5b824ebb22ebbdd22670b00cada67be7a79082707b0ff8b1a.idb"

    extract_info = basicblock_info_extraction(PATH)

    # saved result
    with open(r"D:\out_idb\Andariel\test.result", 'w') as makefile:
        json.dump(extract_info, makefile, ensure_ascii=False, indent='\t')

    # saved error log
    err_log.append('unmatched prime set :' + ' '.join(except_list))
    with open(r"D:\out_idb\Andariel\_logs_" + PATH[PATH.rfind('\\') + 1:-4] + ".log", 'w') as makefile:
        json.dump(err_log, makefile, ensure_ascii=False, indent='\t')

    print(f"[INFO] Total running time : {timeit.default_timer() - s}")  # end time
    print("-----END-----")