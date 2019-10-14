#
import idb
import time
import operator as op
from multiprocessing import Process, current_process,Queue, Pool
import threading
import sys
import signal
import numpy
import indexs_opcode
import operator as op

class idb_info(object):
    def __init__(self, api, fva):
        self.api=api
        self.fva=fva
        self.function=self.api.ida_funcs.get_func(self.fva)

class constant(idb_info):
    registers = ['rax','eax','ax','al','rbx','ebx','bx','bl','rcx','ecx','cx','cl','rdx',
                 'edx','dx','dl','rsi','esi','si','sil','rdi','edi','di','dil','rbp','ebp','bp','bpl','rsp',
                 'esp','sp','spl','r8','r8d','r8w','r8b','r9','r9d','r9w','r9b','r10','r10d','r10w',
                 'r10b','r11','r11d','r11w','r11b','r12','r12d','r12w','r12b','r13','r13d','r13w','r13b',
                 'r14','r14d','r14w','r14b','r15','r15d','r15w','r15b']
    def __init__(self, api, fva):
        super().__init__(api, fva)
    
    
    def constant(self):
        curaddr=self.function.startEA
        result=[]
        while curaddr < self.function.endEA:
            try:
                curaddr = self.api.idc.NextHead(curaddr)
                opcode = self.api.idc.GetMnem(curaddr).upper()
            except:
                continue
            if opcode in indexs_opcode.DATA_TRANSFER or opcode in indexs_opcode.ARIHMETIC or opcode in indexs_opcode.LOGIC:
                operand = self.api.idc._disassemble(curaddr).op_str.split(' ')[-1]
                
                #print(api.idc._disassemble(curaddr).op_str)
            else:
                continue
            if operand in self.registers:
                continue
            try:
                #print(int(operand,16),operand)
                #print(operand)
                straddr=int(operand,16)
                
                #print(opcode,straddr,operand)
                try:
                    self.api.idc.GetFunctionName(straddr)
                    print(straddr)
                except:
                    if straddr > 0x401000 and straddr < 0x500000:
                        continue
                    else:
                        if len(set(str(operand)))<2:
                            continue
                        elif '-' in str(operand):
                            continue
                        result.append(operand)
                        
            except:
                continue
        result = list(set(result))
        return result
######################################################################
def handler(signum, frame):
    raise ValueError
from multiprocessing import Process, current_process,Queue, Pool
def main(api):
    result = []
    max_time_end = time.time() + (60 * 5)
    while True:
        for fva in api.idautils.Functions(): 
            fname = api.idc.GetFunctionName(fva).lower() #<- 렉의 원인
            signal.signal(signal.SIGALRM, handler)
            signal.alarm(222)
            try:
                if fname[:3] == 'sub' or fname[:5] == 'start' or fname.find('main') != -1:

                    cons_object=constant(api, fva)
                    res = cons_object.constant()
                    
                    if len(res)<= 3:
                        continue
                    else:
                        result.append(res)

            except ValueError:
                continue
            if time.time() > max_time_end:
                return result
        
        return result
######################################################################

def CONSTANT_SIMILAR(FROM_FILE,Constant_Queue):
    with idb.from_file(FROM_FILE) as db:
        try:
            api=idb.IDAPython(db)
            CONSTANT_SIMILAR_LIST=main(api)
        except:
             Constant_Queue.put("None")
        Constant_Queue.put(CONSTANT_SIMILAR_LIST)

######################################################################
if __name__=="__main__":
    PATH='/home/bob/Malware_Sample_idb/Andariel/5bb32d3dd8e2624ba7dcac6d9ab86db39e41c7dbd6fe6b82d62488a8938e88a2.idb'
    queue=Queue()
    CONSTANT_SIMILAR_LIST=CONSTANT_SIMILAR(PATH,queue)
    print(CONSTANT_SIMILAR_LIST.get())
