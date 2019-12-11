# -*- coding: utf-8 -*-

import elasticsearch


class ElasticQueryMaster:
    # elastic object
    elastic = None

    index = None

    document = {}
    doc_type = None

    query = {}
    query_result = None
    original_query_result = None

    # EasyQuery
    ssdeep_value = None

    # (dictionary or list) <- search(index="String", query={dictionary}, query_cut_level=[0,1,2])
    #
    # index : elasticsearch 인덱스. 인수로 전달하지 않으면 self.index 를 사용합니다.
    # query : elasticsearch 쿼리. 인수로 전달하지 않으면 self.query 를 사용합니다.
    # query_cut_level : 설정시 결과값을 다듬습니다. 아래 참조
    #
    # ------------------------ cut level 0: 전체 결과를 그대로 출력합니다.
    # {
    #     "took": 5,
    #     "timed_out": false,
    #     "_shards": {
    #         "total": 5,
    #         "successful": 5,
    #         "skipped": 0,
    #         "failed": 0
    #     },
    #     "hits": {
    #         "total": 3938,
    #         "max_score": 444.8173,
    #         "hits": [
    # ------------------------ cut level 1: 데이터와 추가 정보를 출력합니다.
    #             {
    #                 "_index": "basic_block",
    #                 "_type": "record",
    #                 "_id": "IwYML2YBhnA-UBn2PrJg",
    #                 "_score": 444.8173,
    #                 "_source":
    # ------------------------ cut level 2: 데이터만 출력합니다.
    #                   {
    #                     "chunksize": 6,
    #                     "chunk": "vFtlDcNNNNNNN9DB....",
    #                     "double_chunk": "vFtlD8fff9N//5Tv....",
    #                     "ssdeep": "
    def search(self, index=None, query=None, query_cut_level=0):

        index = index if index is not None else self.index
        query = query if query is not None else self.query

        if index is None or query is None:
            raise Exception("올바른 인수가 입력되지 않았습니다.")

        results = self.elastic.search(index, body=query,size=35,request_timeout=30)
        self.original_query_result = results

        if query_cut_level is 0:
            self.query_result = results
        else:
            return_list = []

            for record in results['hits']['hits']:
                if query_cut_level is 2:
                    return_list.append(record['_source'])
                else:
                    return_list.append(record)

            self.query_result = return_list

        return self.query_result

    def insert(self, document=None, index=None, doc_type=None):
        index = index if index is not None else self.index
        document = document if document is not None else self.document
        doc_type = doc_type if doc_type is not None else self.doc_type
        if index is None or document is None or doc_type is None:
            raise Exception("올바른 인수가 입력되지 않았습니다.")

        self.elastic.index(index, doc_type, document)
        # self.elastic.indices.refresh('basic_block')

    def __init__(self, host="localhost:9200"):
        self.query = {"query": {}}
        self.elastic = elasticsearch.Elasticsearch([host])

    # -------------------
    #     Easy Query
    # -------------------

    # -------------------
    #       SSDEEP
    # -------------------

    def ssdeep_query(self, ssdeep_value, save_query=True):
        # if run_search is True and threshold_grade is None:
        #     raise Exception("올바른 인수가 입력되지 않았습니다.")
        chunksize, chunk, double_chunk = ssdeep_value.split(':')
        chunksize = int(chunksize)

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

        if save_query is True:
            self.query = query
        self.ssdeep_value = ssdeep_value
        return query

    def ssdeep_search(self, threshold_grade, index=None, query=None):
        index = index if index is not None else self.index
        query = query if query is not None else self.query

        if index is None or query is None:
            raise Exception("올바른 인수가 입력되지 않았습니다.")

        results = self.elastic.search(index, body=query)

        data_to_return = []

        # require ssdeep
        import ssdeep
        for record in results['hits']['hits']:
            record_ssdeep = record['_source']['ssdeep']
            ssdeep_grade = ssdeep.compare(record_ssdeep, self.ssdeep_value)

            if ssdeep_grade >= threshold_grade:
                record['_source']['ssdeep_grade'] = ssdeep_grade
                data_to_return.append(record['_source'])
            del record

        return data_to_return

    def ssdeep_insert(self, ssdeep=None, index=None, doc_type=None, extra_document=None):
        index = index if index is not None else self.index
        ssdeep = ssdeep if ssdeep is not None else self.ssdeep_value
        doc_type = doc_type if doc_type is not None else self.doc_type

        if index is None or ssdeep is None or doc_type is None:
            raise Exception("올바른 인수가 입력되지 않았습니다.")

        chunksize, chunk, double_chunk = ssdeep.split(':')
        chunksize = int(chunksize)

        document = {
            'chunksize': chunksize,
            'chunk': chunk,
        }

        if extra_document is not None:
            for k, v in extra_document.items():
                document[k] = v

        self.elastic.index(index, doc_type, document)
        self.elastic.indices.refresh('basic_block')


if __name__ == "__main__":
    pass