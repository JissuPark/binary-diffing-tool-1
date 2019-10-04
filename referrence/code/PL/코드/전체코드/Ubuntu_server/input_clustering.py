import ElasticQueryMaster

class clustering: 
    sample_data = {}
    constant_value = [] 
    file_info = {}
    b_b_info = {}
    q_master = ElasticQueryMaster.ElasticQueryMaster()
####################################################################################
    def collect_hash(self, file_hash):
        #print("collect_hash")
        self.sample_data['hash']=file_hash
    def collect_ssdeep_hash(self, ssdeep_hash):
        #print("collect_ssdeep")
        self.sample_data['ssdeep_hash']=ssdeep_hash
    def collect_func_repre(self, func_repre):
        #print("collect_func")
        self.sample_data['func_repre']=func_repre
    def collect_bb_ssdeep(self, bb_ssdeep):
        #print("collect_bb_ssdee")
        self.sample_data['bb_ssdeep']=bb_ssdeep
    def collect_RH(self, rh_info):
        #print("rh_info")
        try:
            if('rh_info' in list(self.sample_data.items()) and self.sample_data['rh_info'] == 'None'):
                self.sample['rh_info'] = 'None'
            self.sample_data['rh_info']=rh_info
        except:
            self.sample_data['rh_info']= 'None'
    def collect_opi(self, opi_info):
        #print("collect_opi")
        self.sample_data['opicode_info']=opi_info
    def collect_constant_value(self, constant_value):
        #print("collect_constant")
        self.constant_value=constant_value
    def print_result(self):
        pass
        #print(self.sample_data)
####################################################################################
    def input_elastic_file_info(self):
        chunksize, chunk, double_chunk = self.file_info["ssdeep_hash"].split(':')
        chunksize = int(chunksize)
        
        file_info = {
              "chunksize": chunksize,
              "chunk": chunk,
              "double_chunk": double_chunk,
              "ssdeep": self.file_info['ssdeep_hash'],  
              "sha256": self.file_info['sha256'],
              "rh_info": self.file_info['rh'],
              "constant_value": "",
              "tag":""
        }
        self.q_master.insert(document=file_info, index="web-fileinfo", doc_type="record")
        
    def input_elastic_basicblock_info(self):
        
        chunksize, chunk, double_chunk = self.b_b_info["bb_ssdeep"].split(':')
        chunksize = int(chunksize)
        
        bb_info = {
            "chunksize": chunksize,
            "chunk": chunk,
            "double_chunk": double_chunk,
            "ssdeep": self.b_b_info['bb_ssdeep'],
            "file-sha256": self.b_b_info['sha256'],
            "func_repre" : self.b_b_info['func_repre'],
            "bb_number": self.b_b_info['bb_number'],
            "opicode_info": self.b_b_info['opicode_info'],
        }
            
        self.q_master.insert(document=bb_info, index="web-basicblock", doc_type="record")
        
    def hash_Duplicate_check(self):
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"sha256": self.sample_data['hash']}},
                    ]
                }
            }
        }
        return(self.q_master.search(index="web-fileinfo", query=query)['hits']['total'])
        
    
    def input_constatnt_value(self):
        for constant_value in self.constant_value:
            chunksize, chunk, double_chunk = constant_value.split(':')
            chunksize = int(chunksize)
            constant_input= {
                "chunksize" : chunksize,
                "chunk" : chunk,
                "double_chunk": double_chunk,
                "ssdeep": constant_value,
                "sha256": self.sample_data['hash'],
                "tag": ""
            }
            self.q_master.insert(document=constant_input, index="web-constant", doc_type="record")

    def metadata_parsing(self):
        print("clustering start!!")
        
        # 중복값 Check
        if(self.hash_Duplicate_check()>=1):
            self.file_info = {}
            self.sample_data = {}
            self.b_b_info = {}
            return False

        self.file_info['sha256'] = self.sample_data['hash']
        self.file_info['ssdeep_hash'] = self.sample_data['ssdeep_hash']
        try:
            self.file_info['rh'] = self.sample_data['rh_info']
        except:
            self.file_info['rh'] = 'None'
        
        self.input_elastic_file_info() 
        self.input_constatnt_value()
        
        for i in range(0,len(self.sample_data['opicode_info'])):
            self.b_b_info['sha256'] = self.sample_data['hash']
            try:
                self.b_b_info['func_repre'] = self.sample_data['func_repre'][i]
            except:
                self.b_b_info['func_repre'] = ''
            self.b_b_info['bb_ssdeep'] = self.sample_data['bb_ssdeep'][i]
            self.b_b_info['opicode_info'] = self.sample_data['opicode_info'][i]
            self.b_b_info['bb_number']=i
            
            # input elastic basicblock_info
            self.input_elastic_basicblock_info()
            #print("basicblock_info input ok")
            self.b_b_info = {}
        #print("success")
        self.file_info = {}
        self.sample_data = {}
        self.b_b_info = {}
        return True