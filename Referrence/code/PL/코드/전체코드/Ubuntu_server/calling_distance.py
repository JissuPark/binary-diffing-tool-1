# Author : 
import idb
import time
import threading
import sys
import signal
import numpy

distance_list=[]
def handler(signum, frame):
    raise ValueError 

def calling_distance(api,fva):
    for addr in api.idautils.XrefsTo(fva,flags=2):
        #print(hex(addr))
        try:
            calling_function = api.ida_funcs.get_func(addr)
            distance = abs(calling_function.startEA-fva)
            distance_list.append(distance)
        except:
            pass

def main(api):
    result = None
    max_time_end = time.time() + (60 * 5)
    while True:
        for fva in api.idautils.Functions(): 
            fname = api.idc.GetFunctionName(fva).lower() #<- 렉의 원인
            #signal.signal(signal.SIGALRM, handler)
            #signal.alarm(222)
            try:
                if fname[:3] == 'sub' or fname[:5] == 'start' or fname.find('main') != -1:
                    #print(fname)
                    calling_distance(api, fva)
                    result = numpy.std(distance_list)

            except ValueError:
                continue
            if time.time() > max_time_end:
                return result
        
        return result
    
def CONSTANT_SIMILAR(FROM_FILE):
    with idb.from_file(FROM_FILE) as db:
        api=idb.IDAPython(db)
        CONSTANT_SIMILAR_LIST=main(api)
        return CONSTANT_SIMILAR_LIST

if __name__=="__main__":
    PATH="/workspace/MandM_DB_INSERT3/IDB_TMP/Idb_Sample/0bde158a7db85a75ceae1def9a54fc2be58fbe7ded5265985d573ae8d4f398fc.idb"
    CONSTANT_SIMILAR_LIST=CONSTANT_SIMILAR(PATH)
    print(CONSTANT_SIMILAR_LIST)