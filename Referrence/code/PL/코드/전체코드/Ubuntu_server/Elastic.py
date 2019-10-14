import elasticsearch
import ssdeep
import json
from time import time

#BLOCK_COUNT = BLOCK ID



###############################################################################



#1단계
#파일 ssdeep 값을 이용한 검색
def get_matching_items_by_ssdeep(ssdeep_value, threshold_grade):
    """
    A function that finds matching items by ssdeep comparison with optimizations using ElasticSearch
    :param ssdeep_value: The ssdeep hash value of the item
    :param threshold_grade: The grade being used as a threshold, only items that pass this grade will be returned
    :return: A List of matching items (in this case, a list of sha256 hash values)
    """
    chunksize, chunk, double_chunk = ssdeep_value.split(':')
    chunksize = int(chunksize)

    es = elasticsearch.Elasticsearch(['localhost:9200'])

    query = {
        'query': {
            'bool': {
                'must': [
                    {
                        'terms': {
                            'chunksize': [chunksize, chunksize * 2, int(chunksize / 2)]
                        }
                    },
                    {
                        'bool': {
                            'should': [
                                {
                                    'match': {
                                        'chunk': {
                                            'query': chunk
                                        }
                                    }
                                },
                                {
                                    'match': {
                                        'double_chunk': {
                                            'query': double_chunk
                                        }
                                    }
                                }
                            ],
                            'minimum_should_match': 0
                        }
                    }
                ]
            }
        }
    }
    

    results = es.search('malware_info', body=query)

    data_to_return = []
    
    # print("HIT COUNT: {}".format(str(len(sha256_list_to_return))))

    for record in results['hits']['hits']:
        #print(record)
        record_ssdeep = record['_source']['ssdeep']
        ssdeep_grade = ssdeep.compare(record_ssdeep, ssdeep_value)
        #print(ssdeep_grade)

        if ssdeep_grade >= threshold_grade:
            data_to_return.append([
                ssdeep_grade,
                record['_source']['ssdeep'],
                record['_source']['sha256'],
                record['_source']['file_name'],
                record['_source']['group'],
                record['_source']['last_updated'],
                record['_source']['tag'],
                record['_source']['upload_date']
            ])
        del(record)

    # not only sha 256!!!!!!! ! !! ! !!!!! !!!!
    return data_to_return

#2단계 함수 대푯값을 이용한 검색

# type=block_representative or type=sha256
# block_representative으로 할 경우 함수 대푯값을 이용해 검색하고
# sha256일 경우 파일의 sha256으로 찾는 것 입니다.

#def search_representative_value(sha256, search_type="block_representative")
def search_representative_value(sha256, search_type="block_representative"):
    query = {
      "query": {
        "match": {
          search_type: sha256
        }
      }
    }
    es = elasticsearch.Elasticsearch(['localhost:9200'])
    results = es.search('basic_block', body=query)
    
    return_list = []

    for record in results['hits']['hits']:

        return_list.append([
            record['_source']['block_representative'],
            record['_source']['sha256_file'],
            record['_source']['block_count'],
            record['_source']['opcode']
        ])
    del(record)
    return return_list


# 귀찮아서 넣은거 ㅇㅋ
# search_everything(인덱스 이름, 서치할 이름(?), 서치할 값)
# 100% 일치시 동작함
# 파일sha256으로 그룹 검색시 아래와 같이 작성.
# result = search_everything("malware_info", "sha256", "여기다가 파일 sha256")
# for thing in result:
#     print(thing["group"])
# 하면 sha256으로 찾아서 그룹을 출력해주겠죠? 
# malware_info이런거요 mysql로 따지면 테이블 같은거임




#테이블 검색 개편함
###############################################################################
# def search_everything(index_name , search_type, search_value):
#     query = {
#       "query": {
#         "match": {
#           search_type: search_value
#         }
#       }
#     }
#     results = es.search(index_name, body=query)

#     return results['hits']['hits']


#INSERT
###############################################################################

#넣어야 할 것
#파일 ssdeep 값을 기준으로 삽입
def insert_record_to_ssdeep_index(data):
    chunksize, chunk, double_chunk = data["ssdeep_value"].split(':')
    chunksize = int(chunksize)
    
    # data는 아래와 같이 넘겨주세요.
    #
    # data = {
    #     'ssdeep_value': "ssdeep 값",
    #     'file_name': "파일 이름",
    #     'group': "그룹 이름 또는 unknown",
    #     'last_updated': "마지막 업데이트. 없으면 업로드날짜랑 같게 (integer <unixtimestamp>)",
    #     'sha256': "sha256 해시",
    #     'tag': ["이런식으로", "태그", "삽입", "없으면", "[]"],
    #     'upload_date': "업로드 날짜 (integer <unixtimestamp>)"
    # }
    # insert_record_to_ssdeep_index(data)

    es = elasticsearch.Elasticsearch(['localhost:9200'])

    document = {
        'chunksize': chunksize,
        'chunk': chunk,
        'double_chunk': double_chunk,
        'ssdeep': data["ssdeep_value"],
        'sha256': data["sha256"],
        'file_name': data["file_name"],
        'group': data["group"],
        'last_updated': data["last_updated"],
        'tag': data["tag"],
        'upload_date': data["upload_date"]
    }

    es.index('malware_info', 'record', document)
    es.indices.refresh('malware_info')
    del(document)
    # last_updated 18-09-22-18-32 done.
    
def insert_basic_block(data):
    chunksize, chunk, double_chunk = data["ssdeep_value"].split(':')
    chunksize = int(chunksize)
    
    # data는 아래와 같이 넘겨주세요.
    #
    # data = {
        # 'ssdeep': ssdeep값,
        # 'sha256': 파일sha256값,
        # 'group': 그룹 이름,
        # 'tag': ["이런식으로", "태그", "삽입", "없으면", "[]"],
        # 'block_representative': basic_block 대푯값,
        # 'block_count': 베이직 블록 번호,
        # 'opcode': 오피코드 전체,
    # }
    # insert_basic_block(data)

    es = elasticsearch.Elasticsearch(['localhost:9200'])

    document = {
        'chunksize': chunksize,
        'chunk': chunk,
        'double_chunk': double_chunk,
        'ssdeep': data["ssdeep_value"], #베이직 블록 SSDEEP 값
        'sha256': data["sha256"], 
        'group': data["group"],
        'tag': data["tag"],
        'block_representative': data["block_representative"], # 베이직 블록 함수 대푯값
        'block_count': data["block_count"],
        'opcode': data["opcode"],
        'disassemble': data["disassemble"],
    }

    es.index('basic_block', 'record', document)
    es.indices.refresh('basic_block')
    del(document)
    # last_updated 18-09-29-14-10 done.


def constant_ssdeep_insert(data):
    chunksize, chunk, double_chunk = data["constant_value"].split(':')
    chunksize = int(chunksize)
    
    # data는 아래와 같이 넘겨주세요.
    #
    # data = {
        # 'ssdeep': ssdeep값,
        # 'sha256': 파일sha256값,
        # 'group': 그룹 이름,
        # 'tag': ["이런식으로", "태그", "삽입", "없으면", "[]"],
        # 'block_representative': basic_block 대푯값,
        # 'block_count': 베이직 블록 번호,
        # 'opcode': 오피코드 전체,
    # }
    # insert_basic_block(data)

    es = elasticsearch.Elasticsearch(['localhost:9200'])

    document = {
        'chunksize': chunksize,
        'chunk': chunk,
        'double_chunk': double_chunk, 
        'sha256': data["sha256"], 
        'group': data["group"],
        'filename':data['filename'],
        'constant_value': data["constant_value"]
    }

    es.index('constant-value', 'record', document)
    es.indices.refresh('constant-value')
    del(document)
    # last_updated 18-09-29-14-10 done.

def find_constant_ssdeep(ssdeep_value, threshold_grade):
    """
    A function that finds matching items by ssdeep comparison with optimizations using ElasticSearch
    :param ssdeep_value: The ssdeep hash value of the item
    :param threshold_grade: The grade being used as a threshold, only items that pass this grade will be returned
    :return: A List of matching items (in this case, a list of sha256 hash values)
    """
    chunksize, chunk, double_chunk = ssdeep_value.split(':')
    chunksize = int(chunksize)

    es = elasticsearch.Elasticsearch(['localhost:9200'])

    query = {
        'query': {
            'bool': {
                'must': [
                    {
                        'terms': {
                            'chunksize': [chunksize, chunksize * 2, int(chunksize / 2)]
                        }
                    },
                    {
                        'bool': {
                            'should': [
                                {
                                    'match': {
                                        'chunk': {
                                            'query': chunk
                                        }
                                    }
                                },
                                {
                                    'match': {
                                        'double_chunk': {
                                            'query': double_chunk
                                        }
                                    }
                                }
                            ],
                            'minimum_should_match': 0
                        }
                    }
                ]
            }
        }
    }
    

    results = es.search('constant-value', body=query)

    data_to_return = []
    
    # print("HIT COUNT: {}".format(str(len(sha256_list_to_return))))

    for record in results['hits']['hits']:
        #print(record)
        record_ssdeep = record['_source']['constant_value']
        ssdeep_grade = ssdeep.compare(record_ssdeep, ssdeep_value)
        #print(ssdeep_grade)
        
        record['_source']['ssdeep_grade'] = ssdeep_grade

        if ssdeep_grade >= threshold_grade:
            data_to_return.append(record['_source'])
        del(record)

    return data_to_return
    
def find_basic_block_by_ssdeep(ssdeep_value, threshold_grade):
    """
    A function that finds matching items by ssdeep comparison with optimizations using ElasticSearch
    :param ssdeep_value: The ssdeep hash value of the item
    :param threshold_grade: The grade being used as a threshold, only items that pass this grade will be returned
    :return: A List of matching items (in this case, a list of sha256 hash values)
    """
    chunksize, chunk, double_chunk = ssdeep_value.split(':')
    chunksize = int(chunksize)

    es = elasticsearch.Elasticsearch(['localhost:9200'])

    query = {
        'query': {
            'bool': {
                'must': [
                    {
                        'terms': {
                            'chunksize': [chunksize, chunksize * 2, int(chunksize / 2)]
                        }
                    },
                    {
                        'bool': {
                            'should': [
                                {
                                    'match': {
                                        'chunk': {
                                            'query': chunk
                                        }
                                    }
                                },
                                {
                                    'match': {
                                        'double_chunk': {
                                            'query': double_chunk
                                        }
                                    }
                                }
                            ],
                            'minimum_should_match': 0
                        }
                    }
                ]
            }
        }
    }
    

    results = es.search('basic_block', body=query)

    data_to_return = []
    
    # print("HIT COUNT: {}".format(str(len(sha256_list_to_return))))

    for record in results['hits']['hits']:
        #print(record)
        record_ssdeep = record['_source']['ssdeep']
        ssdeep_grade = ssdeep.compare(record_ssdeep, ssdeep_value)
        #print(ssdeep_grade)
        
        record['_source']['ssdeep_grade'] = ssdeep_grade

        if ssdeep_grade >= threshold_grade:
            data_to_return.append(record['_source'])
        del(record)

    return data_to_return


    

    
#추후 추가
###############################################################################
def insert_malware_info(data):
    es = elasticsearch.Elasticsearch(['localhost:9200'])

    # data는 아래와 같이 넘겨주세요.
    #
    # data = {
    #     'file_name': "파일 이름",
    #     'group': "그룹 이름 또는 unknown",
    #     'last_updated': "마지막 업데이트. 없으면 업로드날짜랑 같게",
    #     'sha256': "sha256 해시",
    #     'tag': ["이런식으로", "태그", "삽입", "없으면", "[]"],
    #     'upload_date': "업로드 날짜"
    # }
    # insert_malware_info(data)

    es.index('malware_info', 'record', data)
    es.indices.refresh('malware_info')
    del(data)
    
def get_malware_info(search_type, value):
    query = {
      "query": {
        "match": {
          search_type: value
        }
      }
    }
    
    results = es.search('malware_info', body=query)
    del(query)
    return results['hits']['hits']
    
    
#베이직 블록의 함수 대푯값을 삽입
def insert_record_to_representative_value(block_representative, sha256_file, block_count, opcode):
    es = elasticsearch.Elasticsearch(['localhost:9200'])

    document = {
        'block_representative': block_representative,
        'sha256_file': sha256_file, 
        'block_count': block_count, 
        "opcode": opcode
    }

    es.index('basic_block', 'record', document)
    es.indices.refresh('basic_block')
    del(document)
    
import elasticsearch
import ssdeep
import json
from time import time

#BLOCK_COUNT = BLOCK ID



###############################################################################

#1단계
#파일 ssdeep 값을 이용한 검색
def get_matching_items_by_ssdeep(ssdeep_value, threshold_grade):
    """
    A function that finds matching items by ssdeep comparison with optimizations using ElasticSearch
    :param ssdeep_value: The ssdeep hash value of the item
    :param threshold_grade: The grade being used as a threshold, only items that pass this grade will be returned
    :return: A List of matching items (in this case, a list of sha256 hash values)
    """
    chunksize, chunk, double_chunk = ssdeep_value.split(':')
    chunksize = int(chunksize)

    es = elasticsearch.Elasticsearch(['localhost:9200'])

    query = {
        'query': {
            'bool': {
                'must': [
                    {
                        'terms': {
                            'chunksize': [chunksize, chunksize * 2, int(chunksize / 2)]
                        }
                    },
                    {
                        'bool': {
                            'should': [
                                {
                                    'match': {
                                        'chunk': {
                                            'query': chunk
                                        }
                                    }
                                },
                                {
                                    'match': {
                                        'double_chunk': {
                                            'query': double_chunk
                                        }
                                    }
                                }
                            ],
                            'minimum_should_match': 0
                        }
                    }
                ]
            }
        }
    }
    

    results = es.search('malware_info', body=query)

    data_to_return = []
    
    # print("HIT COUNT: {}".format(str(len(sha256_list_to_return))))

    for record in results['hits']['hits']:
        #print(record)
        record_ssdeep = record['_source']['ssdeep']
        ssdeep_grade = ssdeep.compare(record_ssdeep, ssdeep_value)
        #print(ssdeep_grade)

        if ssdeep_grade >= threshold_grade:
            data_to_return.append([
                ssdeep_grade,
                record['_source']['ssdeep'],
                record['_source']['sha256'],
                record['_source']['file_name'],
                record['_source']['group'],
                record['_source']['last_updated'],
                record['_source']['tag'],
                record['_source']['upload_date']
            ])
        del(record)

    # not only sha 256!!!!!!! ! !! ! !!!!! !!!!
    return data_to_return

#2단계 함수 대푯값을 이용한 검색

# type=block_representative or type=sha256
# block_representative으로 할 경우 함수 대푯값을 이용해 검색하고
# sha256일 경우 파일의 sha256으로 찾는 것 입니다.

#def search_representative_value(sha256, search_type="block_representative")
def search_representative_value(sha256, search_type="block_representative"):
    query = {
      "query": {
        "match": {
          search_type: sha256
        }
      }
    }
    es = elasticsearch.Elasticsearch(['localhost:9200'])
    results = es.search('basic_block', body=query)
    
    return_list = []

    for record in results['hits']['hits']:

        return_list.append([
            record['_source']['block_representative'],
            record['_source']['sha256_file'],
            record['_source']['block_count'],
            record['_source']['opcode']
        ])
    return return_list


# 귀찮아서 넣은거 ㅇㅋ
# search_everything(인덱스 이름, 서치할 이름(?), 서치할 값)
# 100% 일치시 동작함
# 파일sha256으로 그룹 검색시 아래와 같이 작성.
# result = search_everything("malware_info", "sha256", "여기다가 파일 sha256")
# for thing in result:
#     print(thing["group"])
# 하면 sha256으로 찾아서 그룹을 출력해주겠죠? 
# malware_info이런거요 mysql로 따지면 테이블 같은거임

def search_everything(index_name , search_type, search_value):
    query = {
      "query": {
        "match": {
          search_type: search_value
        }
      }
    }
    es = elasticsearch.Elasticsearch(['localhost:9200'])
    results = es.search(index_name, body=query)
    
    return_list = []
    
    for record in results['hits']['hits']:
        record['_source']['_id']=record['_id']
        return_list.append(
            record['_source']
        )
        
    return return_list


def _search_query(index, query, everything=False):
    es = elasticsearch.Elasticsearch(['localhost:9200'])
    results = es.search(index, body=query)
    
    return_list = []
    
    for record in results['hits']['hits']:

        if everything is False:
            try:
                return_list.append(record['_source'])
            except NameError:
                pass
        else:
            return_list.append(record)
        
    return return_list


#INSERT
###############################################################################

#넣어야 할 것
#파일 ssdeep 값을 기준으로 삽입
def insert_record_to_ssdeep_index(data):
    chunksize, chunk, double_chunk = data["ssdeep_value"].split(':')
    chunksize = int(chunksize)
    
    # data는 아래와 같이 넘겨주세요.
    #
    # data = {
    #     'ssdeep_value': "ssdeep 값",
    #     'file_name': "파일 이름",
    #     'group': "그룹 이름 또는 unknown",
    #     'last_updated': "마지막 업데이트. 없으면 업로드날짜랑 같게 (integer <unixtimestamp>)",
    #     'sha256': "sha256 해시",
    #     'tag': ["이런식으로", "태그", "삽입", "없으면", "[]"],
    #     'upload_date': "업로드 날짜 (integer <unixtimestamp>)"
    # }
    # insert_record_to_ssdeep_index(data)

    es = elasticsearch.Elasticsearch(['localhost:9200'])

    document = {
        'chunksize': chunksize,
        'chunk': chunk,
        'double_chunk': double_chunk,
        'ssdeep': data["ssdeep_value"],
        'sha256': data["sha256"],
        'file_name': data["file_name"],
        'group': data["group"],
        'last_updated': data["last_updated"],
        'tag': data["tag"],
        'upload_date': data["upload_date"]
    }

    es.index('malware_info', 'record', document)
    es.indices.refresh('malware_info')
    del(document)
    # last_updated 18-09-22-18-32 done.

#베이직 블록의 함수 대푯값을 삽입
def insert_record_to_representative_value(block_representative, sha256_file, block_count, opcode):
    es = elasticsearch.Elasticsearch(['localhost:9200'])

    document = {
        'block_representative': block_representative,
        'sha256_file': sha256_file, 
        'block_count': block_count, 
        "opcode": opcode
    }

    es.index('basic_block', 'record', document)
    es.indices.refresh('basic_block')
    del(document)
    

    
#추후 추가
###############################################################################
def insert_malware_info(data):
    es = elasticsearch.Elasticsearch(['localhost:9200'])

    # data는 아래와 같이 넘겨주세요.
    #
    # data = {
    #     'file_name': "파일 이름",
    #     'group': "그룹 이름 또는 unknown",
    #     'last_updated': "마지막 업데이트. 없으면 업로드날짜랑 같게",
    #     'sha256': "sha256 해시",
    #     'tag': ["이런식으로", "태그", "삽입", "없으면", "[]"],
    #     'upload_date': "업로드 날짜"
    # }
    # insert_malware_info(data)

    es.index('malware_info', 'record', data)
    es.indices.refresh('malware_info')
    del(data)
    
def get_malware_info(search_type, value):
    query = {
      "query": {
        "match": {
          search_type: value
        }
      }
    }
    
    results = es.search('malware_info', body=query)
    del(query)
    return results['hits']['hits']
    
def rich_header_insert(data):
    es = elasticsearch.Elasticsearch(['localhost:9200'])

    document = {
        'file_name': data["file_name"],
        'sha256': data["sha256"],
        'rich_header': data["rich_header"],
        'group': data["group"]
    }

    es.index('rich-header', 'record', document)
    es.indices.refresh('rich-header')
    del(document)
    # last_updated 18-10-01-21-56 done.

if __name__=="__main__":
    #6:vFtlDcNNNNNNN9DBHFVDLHF3TvDNT3TNN9Dr3TvDNfDjDn3TG9jDn3TfgZTvs0:vFtlD8fff9N//5TvRjTf9PTvRfnbTGV
    #Bluenoroff
    # matching_items = get_matching_items_by_ssdeep("6144:PtjHqmEoKz3IIjt4BWR2+GMhduUW3Rkp3btSokgyrx:PtjH0oKz3IiTR2+Th0RY3btXyrx", 85)
    # print(matching_items)
    
    query = {
        "query": {
            "bool": {
                "must": [
                    { "match": { "group" : "Bluenoroff" }},
                    { "match": { "block_representative": "48338b3c5648fed96751264a54c4e7be8f4d41a5f5790cf32df50a21f70fb856"}}
                ]
            }    
        }
    }
    result_list = _search_query("basic_block", query)
    if len(result_list)>0:
        for result in result_list:
            print(result)
    
    
    
