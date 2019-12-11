import Elastic
import ElasticQueryMaster

if __name__ == '__main__':
    
    q_master = ElasticQueryMaster.ElasticQueryMaster()
    r_open = open('/home/bob/Main_Project/Whitelist/White_list.txt','r',encoding='utf-8')
    
    white_list=r_open.readlines()
    
    for hash in white_list:
        document = {
                'white_hash': hash
        }
        q_master.insert(document=document, index="??", doc_type="record")