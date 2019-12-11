# Author : 
import idb
import time
import threading
import sys
import signal
import operator as op

class basic_block:
    def __init__(self, startaddr, endaddr, opcode,disasms):
        self.startaddr = startaddr
        self.endaddr = endaddr
        self.opcode = opcode
        self.disasms=disasms
        
        
        
def handler(signum, frame):
    raise ValueError 
    
def main(api):
    result = []
    res=[]
    fname_list=[]
    max_time_end = time.time() + (60 * 5)
    while True:
        for fva in api.idautils.Functions(): 
            fname = api.idc.GetFunctionName(fva).lower() #<- 렉의 원인

            if fname[:3] == 'sub' or fname[:5] == 'start' or fname.find('main') != -1:
                fname_list.append(fname)
        
        if len(fname_list)<9:
            for fva in api.idautils.Functions(): 
                fname = api.idc.GetFunctionName(fva).lower() #<- 렉의 원인


                if fname[:3] == 'sub' or fname[:5] == 'start' or fname.find('main') != -1 or fname[:6]=='winmain':
                    res = print_all_bbs(api, fva,20)
                    if res == []:
                        continue
                    else:
                        result.append(res)
                else:
                    continue

                if time.time() > max_time_end:
                    return result

            return result
        else:
            for fva in api.idautils.Functions(): 
                fname = api.idc.GetFunctionName(fva).lower() #<- 렉의 원인

                if fname[:3] == 'sub' or fname[:5] == 'start' or fname.find('main') != -1 or fname[:6]=='winmain':
                    if fname[0]!='?':
                        res = print_all_bbs(api, fva,60)

                        if res == []:
                            continue
                        else:
                            result.append(res)
                else:
                    continue
                if time.time() > max_time_end:
                    return result
            return result

    
def print_all_bbs(api, fva,max_count):
    function = api.ida_funcs.get_func(fva)
    flowchart = api.idaapi.FlowChart(function)
    result = []   
    count=0    
    for bb in flowchart:    
        if count==0:
            fnames_bb=api.idc.GetFunctionName(bb.startEA).lower()
            
            #print(fnames_bb)
            if fnames_bb[:3] == 'sub' or fnames_bb[:5] == 'start' or fnames_bb.find('main') != -1 or fnames_bb[:6]=='winmain':
                if fnames_bb[0]!='?':

                        
                    curaddr = bb.startEA

                    opcodes = []
                    disasms=[]
                    if (bb.endEA - bb.startEA) < max_count:
                        count=op.add(count,1)
                        continue
                    #print(fnames_bb)      
                    #print("\tStart : {}".format(hex(bb.startEA)))
                    #print("\tEnd : {}".format(hex(bb.endEA)))
                    while curaddr < bb.endEA:
                        opcode = api.idc.GetMnem(curaddr)
                        disasm=api.idc.GetDisasm(curaddr)
                        
                        
                        opcodes.append(opcode)
                        disasms.append(disasm)
                        curaddr = api.idc.NextHead(curaddr)
                    result.append(bb.startEA, bb.endEA, disasms)
                    count=op.add(count,1)
                    continue
            else:
                return None
        else:
            curaddr = bb.startEA
            opcodes = []
            if (bb.endEA - bb.startEA) < max_count:
                count=op.add(count,1)
                continue

            fnames_bb=api.idc.GetFunctionName(bb.startEA).lower()
            if '_' in fnames_bb:
                continue
            else:
                pass

            while curaddr < bb.endEA:
                opcode = api.idc.GetMnem(curaddr)
                disasm=api.idc.GetDisasm(curaddr)

                opcodes.append(opcode)
                disasms.append(disasm)

                curaddr = api.idc.NextHead(curaddr)
            result.append(bb.startEA, bb.endEA, disasms)
            count=op.add(count,1)
            continue


        del(opcodes)
    return result


def open_idb(FROM_FILE):
    with idb.from_file(FROM_FILE) as db:
        api=idb.IDAPython(db)
        return api

def BASIC_BLOCK_IDB(FROM_FILE):
    api = open_idb(FROM_FILE)
    BASIC_BLOCK_RESULT_LIST = main(api)
    return BASIC_BLOCK_RESULT_LIST



if __name__=="__main__":
    PATH = "D:\\Allinone\\Programing\\Python\\Study\\convert_pe_idb\\idb_sample\\579c374bdfcec2f9c66a44295b124801fb5ecc3b9ccc80d82c6b006edac4841a.idb"
    BASIC_BLOCK_RESULT_LIST=BASIC_BLOCK_IDB(PATH)
    print(BASIC_BLOCK_RESULT_LIST)