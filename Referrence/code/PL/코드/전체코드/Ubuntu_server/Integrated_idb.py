import idb
import time
import threading
import sys
import signal
import numpy
import operator as op
from multiprocessing import Process, current_process,Queue, Pool
#from projects.bin from *
#from decompiler import *

#만든 모듈
import constant_similarity
import indexs_opcode
import pseudocode
#####################################################################################
class idb_info(object):
    def __init__(self, api, fva):
        self.api=api
        self.fva=fva
        self.function=self.api.ida_funcs.get_func(self.fva)
#####################################################################################
class basic_block(idb_info):
    def __init__(self, api, fva, func_name):
        super(basic_block, self).__init__(api, fva)
        self.func_name = func_name
    def set_op_and_asm(self,startaddr,endaddr,opcode,disasms,pseudo):    
        self.startaddr = startaddr
        self.endaddr = endaddr
        self.opcode = opcode
        self.disasms=disasms
        self.pseudo=pseudo
        return self

    def bbs(self):
        mutex_opcode_list=[]
        flowchart = self.api.idaapi.FlowChart(self.function)
        result = []
        try:
            pseudo = pseudocode.make_pesudo(self.func_name)
        except:
            pseudo = "None"
            pass
        #print(pseudo)
        for bb in flowchart:
            curaddr = bb.startEA
            opcodes = []
            disasms=[]
            #최소 바이트 50이상 할것
            if (bb.endEA - bb.startEA) < 35:
                continue
            try:
                while curaddr <= bb.endEA:
                    opcode = self.api.idc.GetMnem(curaddr)
                    disasm=self.api.idc.GetDisasm(curaddr)
                    opcodes.append(opcode)
                    disasms.append(disasm)
                    curaddr = self.api.idc.NextHead(curaddr)
            except:
                continue
            
            #중복 값 제어
            mutex_opcode=' '.join(opcodes)
            if mutex_opcode in mutex_opcode_list:
                continue
            else:mutex_opcode_list.append(mutex_opcode)
            
            result.append(self.set_op_and_asm(bb.startEA, bb.endEA, opcodes,disasms,pseudo))
            del(opcodes)
            del(disasms)
        if result == []:
            result = None
        return result
#####################################################################################
distance_list=[]
class calling_distance(idb_info):
    
    def __init__(self, api, fva):
        super().__init__(api, fva)

    def calling_distance(self):
        for addr in self.api.idautils.XrefsTo(self.fva,flags=2):
            #print(hex(addr))
            try:
                calling_function = self.api.ida_funcs.get_func(addr)
                distance = abs(calling_function.startEA-self.fva)
                distance_list.append(distance)
            except:
                pass
                
#####################################################################################
#def handler(signum, frame):
#    raise ValueError
#####################################################################################

def main(api,FROM_FILE):
    
    result_call = []
    result_distance = None
    
    Constant_Queue=Queue()
    constant_Thread = Process(target=constant_similarity.CONSTANT_SIMILAR, args=(FROM_FILE,Constant_Queue,))
    constant_Thread.start()
    
    max_time_end = time.time() + (60 * 5)
    for fva in api.idautils.Functions():
        #print(fva)
        fname = api.idc.GetFunctionName(fva).lower()
        #signal.signal(signal.SIGALRM, handler)
        #signal.alarm(660)
        #print(fname)
        try:
            if  'dllentry' in fname or fname[:3] == 'sub' or fname[:5] == 'start' or fname.find('main') != -1:#main or start or sub_***** function. not library function
                
                    #start_time=time.time()
                call = calling_distance(api,fva)
                call.calling_distance()
                    #end_time=time.time()
                    #print("Calling Distance : {}".format(end_time-start_time))
                    
                    
                    #start=time.time()
                
                bb = basic_block(api,fva,fname.replace("sub","function"))
                bb_result = bb.bbs()
                    #end_time=time.time()
                    #print("BasicBlock : {}".format(end_time-start_time))
                    
                    
                if bb_result == None:
                    pass
                else :
                    result_call.append(bb_result)
                    
        except:
            continue
        if time.time() > max_time_end:
            result_distance = numpy.std(distance_list)
            
            #start_time=time.time()
            constant_Thread.join()
            result_constant=Constant_Queue.get()
            #end_time=time.time()
            #print("constant : {}".format(end_time-start_time))
            
            return result_call,result_constant,result_distance
            
            
    result_distance = numpy.std(distance_list)
    
    #start_time=time.time()
    constant_Thread.join()
    result_constant=Constant_Queue.get()
    #end_time=time.time()
    #print("constant : {}".format(end_time-start_time))
            
    
    return result_call,result_constant,result_distance
#######################################################################################


#######################################################################################
def test(FROM_FILE):
    with idb.from_file(FROM_FILE) as db:
        api=idb.IDAPython(db)
        result_call,result_constant,result_distance=main(api,FROM_FILE)
        #print(result_call,result_constant,result_distance)
        return result_call,result_constant,result_distance

if __name__=="__main__":
    start=time.time()
    PATH = "D:\\Allinone\\Programing\\Python\\Study\\convert_pe_idb\\idb_sample\\cc2f8521f5aee23d288afef4477dd385c8cc7a6f65e700097b1ceb08b56674cc.idb"
    result_call,result_constant,result_distance=test(PATH)
    end=time.time()
    print(end-start)
    print(result_call,result_constant,result_distance)
