import sys
import struct
import os
import prodid_map
import hashlib
import ElasticQueryMaster
import json
import input_clustering as cl
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



        


SAMPLE = "/workspace/MandM_DB_INSERT3/Malware_Sample/Bluenoroff/1de2021cc2b7127381ab826f2dedc56fe73c49d5a4e1f193cc967ec0b53dc7df"

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
            rich_addr = data.find(b'Rich')                                              
            self.xorkey = struct.unpack('<I',data[rich_addr + 4:rich_addr + 8])[0]
            self.data = data[:rich_addr]
            for i in range(16, rich_addr, 8):
                key = struct.unpack("<L", self.data[i:i+4])[0] ^ self.xorkey
                count = struct.unpack("<L", self.data[i+4:i+8])[0] ^ self.xorkey
                info = Info(key, count)
                self.info.append(info)
        except:
            del self.info[:]                                                            
            #self.clear_data.append(hex(key))
            #self.clear_data.append(hex(count))
            #self.prodid.append(key >> 16)
        #print(self.clear_data)
        #print(self.prodid)
        #print(hex(self.xorkey))

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
        
def elastic_search_input(rich_information,filename):
    file = filename.split('/')[-1]
    SHA = filename.split('/')[-1]
    group = filename.split('/')[-2]
    xorkey = hex(rich_information.xorkey)
    prodid = rich_information.return_prodid()
    clear_data=rich_information.return_clear_data()
    build = rich_information.return_build()
    count = rich_information.return_count()

    #print(str(clear_data))
    q_master = ElasticQueryMaster.ElasticQueryMaster()

    document = {
        "file_name": file,
          "group": group,
          "rich_header": "",
          "sha256": SHA,
          "xor_key": xorkey,
          "clear_data": clear_data,
          "prod_id": prodid,
          "build": build,
          "count": count
    }
    
    q_master.insert(document=document, index="rich-header", doc_type="record")
    #print(document)
    
    
def search(json_rich_data):
    #sample_file = open(SAMPLE,'rb')
    #sample_rich_information=richheader(sample_file)
    #sample_clear_data=sample_rich_information.return_clear_data()
    #clear = " ".join(sample_clear_data)
    clear=' '.join(json_rich_data['sample_clear_data'])
    print(clear)
    cl.clustering().collect_RH(clear)
    q_master = ElasticQueryMaster.ElasticQueryMaster()
    q_master.query = {
        "query": {
            "match": {
                "clear_data": clear
            }
        }
    }
    result=q_master.search(index="rich-header", query_cut_level=0)
    
    return result
    

class compare_data:
    def __init__(self,groups,sha_256,xor_key,build,count,prodid_list):
        self.groups=groups
        self.sha256=sha_256
        self.xor_key=xor_key
        self.build=build
        self.count=count
        self.prodid_list=prodid_list
        self.silmar=set(prodid_list)
        
        
def compare_clear_data(json_rich_data):
   
   
    elastic_result = search(json_rich_data['pe_richheader'])
    clear=' '.join(json_rich_data['pe_richheader']['sample_clear_data'])
    sample_prodid = json_rich_data['pe_richheader']['prodid']
    
    result_list=[]
    for i in range(len(elastic_result)):

        if(elastic_result['hits']['hits'][i]['_source']['clear_data'] == clear):
            groups=str(elastic_result['hits']['hits'][i]['_source']['group'])
            sha_256=json_rich_data['pe_sha256']
            xor_key=json_rich_data['pe_richheader']['xorkey']
            build=json_rich_data['pe_richheader']['build']
            count=json_rich_data['pe_richheader']['count']


                    
            result_list.append(compare_data(groups,sha_256,xor_key,build,count,sample_prodid))
            return result_list
        else:
            print("Result not Find")
            
            
    return result_list
if __name__ == "__main__":
    
    PATH2='/home/bob/0477FF27676537E553F84B5CA3974093E656C7D757EEA8F01C34342D0C042242'
    Rich=richheader(PATH2)
    print(Rich.return_prodid())
    print(Rich.return_build())
    
    '''
    json_file='/home/bob/IDB_TMP/BackUp/json_backup/20181127226367886.json'
    json_file_read=open(json_file,encoding='utf-8').read()
    json_data=json.loads(json_file_read)
    result=compare_clear_data(json_data)
    print(result[0].groups)
    '''