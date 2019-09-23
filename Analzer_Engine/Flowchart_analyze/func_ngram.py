# pip install NGram
# This using import func_ngram as n
# n.get_similarity(path 1, path 2)

from ngram import NGram 
import json
import timeit

def read_json(PATH):
    with open(PATH, "r") as json_file:
        json_data = json.load(json_file)    
    return json_data['constant']


def get_similarity(standard, target): # input json path string 1, 2
    reslut = dict()
    s = read_json(standard)
    t = read_json(target)
    # print(f'[+]Stand Binary(length {len(s)}) ::: target Binary(length {len(t)})')
    for i in range(1, 6):
        # print(f"{i}-GRam: {NGram.compare(s, t, N=i)}")
        reslut.update({str(i)+"-Gram": NGram.compare(s, t, N=i)})
        '''
        return reslut type : dict
        {'1-Gram': reslut, '2-Gram': reslut,  .... '5-Gram': reslut}

        '''
    return reslut




if __name__ == "__main__":
    
    # s = timeit.default_timer() # start time

    # Testing code
    PATH_1 = r"D:\out_idb\ppa_1.txt"
    PATH_2 = r"D:\out_idb\ppa_2.txt"
    gram_result = get_similarity(PATH_1, PATH_2)

    print(gram_result)

    # print(f"[+]running : {timeit.default_timer() - s}") # end time


