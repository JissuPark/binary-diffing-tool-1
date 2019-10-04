# Author : 
import basicblock_idb as BB64
import ssdeep
import mmh3
import hashlib
import idb
import operator as op
import File_Information as FI
    
    

    
#파일 자체에 대한 SSDEEP 값 생성
def SSDEEP_BB_DB_INSERT(BASIC_BLOCK_RESULT_LIST,PATH):
    File_Info=FI.STRINGS()
    try:
        FILE_HASH=PATH.split('/')[-1].replace('.idb','')
    except:
        FILE_HASH=File_Info.getHash(PATH)
        
        
    FUNCTION_REPRE_LIST=[]
    BASIC_BLOCK_INDEX=0
    for FUNC_BLOCK in BASIC_BLOCK_RESULT_LIST:
        #FUNC_BLOCK=["BB1","BB2","BB3"]
        for BASIC_BLOCK in FUNC_BLOCK:
            #BASIC_BLOCK="BB1"
            BASIC_BLOCK_OPCODE_ALL=' '.join(BASIC_BLOCK.opcode)
            SSDEEP_HASHS=ssdeep.hash(BASIC_BLOCK_OPCODE_ALL,encoding='utf-8')
            FUNCTION_REPRE_LIST.append([SSDEEP_HASHS,FILE_HASH,BASIC_BLOCK_INDEX,BASIC_BLOCK_OPCODE_ALL])
            BASIC_BLOCK_INDEX=BASIC_BLOCK_INDEX+1
        del(BASIC_BLOCK_OPCODE_ALL)
    return FUNCTION_REPRE_LIST
                 

# malware_info
#    document = {
#        'chunksize': chunksize,
#        'chunk': chunk,
#        'double_chunk': double_chunk,
#        'ssdeep': data["ssdeep_value"],
#        'sha256': data["sha256"],
#        'file_name': data["file_name"],
#        'group': data["group"],
#       'last_updated': data["last_updated"],
#       'tag': data["tag"],
#        'upload_date': data["upload_date"]
#    }

# basic_block
#    document = {
#        'chunksize': chunksize,
#        'chunk': chunk,
#        'double_chunk': double_chunk,
#        'ssdeep': data["ssdeep_value"], #베이직 블록 SSDEEP 값
#        'sha256': data["sha256"], 
#        'group': data["group"],
#        'tag': data["tag"],
#        'block_representative': data["block_representative"], # 베이직 블록 함수 대푯값
#        'block_count': data["block_count"],
#        'opcode': data["opcode"],
#    }


def OPCODE_CONVERTER(BASIC_BLOCK):
    OPCODE_LIST=[]
    for OPCODE in BASIC_BLOCK:
        OPCODE=hashlib.sha256(str(OPCODE).encode()).hexdigest()
        OPCODE_LIST.append(OPCODE)
    return ' '.join(OPCODE_LIST)
#베이직 블록 함수 대푯값 생성 함수
def FUNCTION_REPRE_DB_INSERT(BASIC_BLOCK_RESULT_LIST,PATH):
    File_Info=FI.STRINGS()
    try:
        FILE_HASH=PATH.split('/')[-1].replace('.idb','')
    except:
        FILE_HASH=File_Info.getHash(PATH)
    FILE_HASH=PATH.split('/')[-1].replace('.idb','')
    FUNCTION_REPRE_LIST=[]
    BASIC_BLOCK_INDEX=0
    MUTEX_LIST=[]
    for FUNC_BLOCK in BASIC_BLOCK_RESULT_LIST:
        #FUNC_BLOCK=["BB1","BB2","BB3"]
        #print("\tFUNC_BLOCK : {}\n".format(FUNC_BLOCK))
        try:
            for BASIC_BLOCK in FUNC_BLOCK:
                #BASIC_BLOCK="BB1"
                BASIC_BLOCK_OPCODE_ALL=' '.join(BASIC_BLOCK.opcode)
                #print("RESULT : {}\n".format(BASIC_BLOCK_OPCODE_ALL))

                #베이직 블록 내 모든 OPCODE HEX로 변환

                STR_CLASS=FI.STRINGS()

                OPCODE_HEX_LIST=[]
                for OPCODE_HEX in BASIC_BLOCK.opcode:
                    OPCODE_HEX_LIST.append(STR_CLASS.STR_HEX_COVERTER(OPCODE_HEX))

                BASIC_BLOCK_OPCODE_HEX=STR_CLASS.STR_ADD(OPCODE_HEX_LIST)

                #베이직 블록 내 opcode에 대한 xor 연산 후 해시 화 -> 함수 대푯값 선정
                HASH_OPCODE=hashlib.sha256(str(BASIC_BLOCK_OPCODE_HEX).encode()).hexdigest()
                #print("OPCODE_HASH_BLOCK : {}\n".format(HASH_OPCODE))
                #HASH_OPCODE는 함수 대푯값을 의미함.

                #CONVERTER_BASEIC_BLOCK_OPCODE=OPCODE_CONVERTER(BASIC_BLOCK.opcode)
                #SSDEEP_HASHS=ssdeep.hash(CONVERTER_BASEIC_BLOCK_OPCODE,encoding='utf-8')

                SSDEEP_HASHS=ssdeep.hash(BASIC_BLOCK_OPCODE_ALL,encoding='utf-8')
                if HASH_OPCODE in MUTEX_LIST:
                    continue
                else:
                    FUNCTION_REPRE_LIST.append([HASH_OPCODE,SSDEEP_HASHS,FILE_HASH,BASIC_BLOCK_INDEX,BASIC_BLOCK_OPCODE_ALL])
                    #FUNCTION_REPRE_LIST.append([HASH_OPCODE,SSDEEP_HASHS,FILE_HASH,BASIC_BLOCK_INDEX,BASIC_BLOCK_OPCODE_ALL,BASIC_BLOCK.startaddr,BASIC_BLOCK.endaddr])
                    BASIC_BLOCK_INDEX=BASIC_BLOCK_INDEX+1
                    MUTEX_LIST.append(HASH_OPCODE)
        except TypeError:
            return None
                

        del(BASIC_BLOCK_OPCODE_ALL)
    del(MUTEX_LIST)
    return FUNCTION_REPRE_LIST


#PLZ INPUT IDB FILE
def BASIC_BLOCK_IDB(FROM_FILE):
    try:
        with idb.from_file(FROM_FILE) as db:
            api=idb.IDAPython(db)
            BASIC_BLOCK_RESULT_LIST=BB64.main(api)
            return BASIC_BLOCK_RESULT_LIST   
    except:
        return None

if __name__=="__main__":
    FROM_FILE='/workspace/MandM_DB_INSERT3/Malware_Sample_idb/Andariel/f7d5a895ccc603f03e6d1a2bb1040147f9c830c6624d76749f69ff23e990f821.idb'
    BASIC_BLOCK_RESULT_LIST=BASIC_BLOCK_IDB(FROM_FILE)
    FUNCTION_REPRE_DB_INSERT(BASIC_BLOCK_RESULT_LIST,FROM_FILE)