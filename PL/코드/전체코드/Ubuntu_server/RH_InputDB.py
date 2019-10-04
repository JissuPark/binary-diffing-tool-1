import sys
import struct
import os
import prodid_map
import hashlib
import ElasticQueryMaster
import File_Information as FI
##############################################################################################
#RH 유사도 측정 스크립트
#1. RH 추출 후 KEY 값을 이용한 XOR 연산 및 Meta Data 추출 
#2. 샘플 값과 DB 값의 Clear_data 비교 
#3. 매칭 시 다음과 같은 데이터 출력이 목표 
# - 해시 
# - 매칭 그룹 
# - XOR KEY : 
# - Prodid, Name, Build, Count 값 표로 출력 
##############################################################################################

DB = "/workspace/RichHeader/malware" 


# male file detect 
class search_route:
    def __init__(self, dir):
        self.dir_names = []
        self.file_names = []
        self.dirname = os.listdir(dir)
        for self.dirname in self.dirname:
            self.dir_names.append(os.path.join(dir, self.dirname))
        for i in self.dir_names:
            for j in os.listdir(i):
                self.file_names.append(os.path.join(i, j) )

    def return_filelst(self):
        return self.file_names

# Rich_header_extraction
class richheader:
    def __init__(self, fp):
        self.info = []
        self.clear_data=[]
        self.prodid = []
        self.xorkey = ""
        try:
            data = fp.read()
            end = struct.unpack('<I', data[0x3c:0x40])[0]
            data = data[0x80:end]
            rich_addr = data.find(b'Rich')                                              # find 'Rich' // Rich 문자열을 찾는다.
            self.xorkey = struct.unpack('<I',data[rich_addr + 4:rich_addr + 8])[0]
            self.data = data[:rich_addr]
            for i in range(16, rich_addr, 8):
                key = struct.unpack("<L", self.data[i:i+4])[0] ^ self.xorkey
                count = struct.unpack("<L", self.data[i+4:i+8])[0] ^ self.xorkey
                info = Info(key, count)
                self.info.append(info)
        except:
            return 0
                                                         
            
    def return_prodid(self):
        set1 = []
        if (len(self.info) != 0):
            for i in self.info:
                set1.append(i.prodid)
        return (set1)
    
    def return_clear_data(self):
        set1 = []
        if (len(self.info) != 0):
            for i in self.info:
                set1.append(hex(i.compid))
                set1.append(hex(i.count))
        return (set1)
    
    def return_build(self):
        set1 = []
        if (len(self.info) != 0):
            for i in self.info:
                set1.append(hex(i.build))
        return (set1)
    
    def return_count(self):
        set1 = []
        if (len(self.info) != 0):
            for i in self.info:
                set1.append(hex(i.count))
        return (set1)

# Extraction result
class Info:
    def __init__(self, compid, count):
        self.compid = compid
        self.prodid = compid >> 16
        self.build = compid & 0xffff
        self.count = count       

        
FI=FI.STRINGS()       
def elastic_search_input(rich_information,filename,group):
    file=os.path.splitext(filename)[1]
    pe_file_hash=FI.getHash(filename)
    group_name = group
    xorkey = hex(rich_information.xorkey)
    prodid = rich_information.return_prodid()
    clear_data=rich_information.return_clear_data()
    clear = " ".join(clear_data)
    build = rich_information.return_build()
    count = rich_information.return_count()
    

    q_master = ElasticQueryMaster.ElasticQueryMaster()

    document = {
        "file_name": file,
          "group": group_name,
          "rich_header": "",
          "sha256": pe_file_hash,
          "xor_key": xorkey,
          "clear_data": clear,
          "prod_id": prodid,
          "build": build,
          "count": count
    }
    print(document)
    q_master.insert(document=document, index="rich-header", doc_type="ecord")

# Main Function
def input_DB(file_path,group):
    try:
        rich_information = richheader(open(file_path, 'rb'))
        if (len(rich_information.info) != 0):
            elastic_search_input(rich_information,file_path,group)
    except:
        return None

if __name__ == "__main__":
    input_DB("/workspace/MandM_DB_INSERT3/Malware_Sample/Bluenoroff/1de2021cc2b7127381ab826f2dedc56fe73c49d5a4e1f193cc967ec0b53dc7df","Bluenoroff")