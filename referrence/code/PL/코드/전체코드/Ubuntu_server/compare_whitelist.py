import Elastic
import ElasticQueryMaster

def compare_whitelist(sample_sha256):
    q_master = ElasticQueryMaster.ElasticQueryMaster()
    query = {
      "query": {
        "match": {
          'white_hash': sample_sha256
        }
      }
    }
    es = q_master.Elasticsearch(['localhost:9200'])
    results = es.search('????', body=query)
    #print(results)