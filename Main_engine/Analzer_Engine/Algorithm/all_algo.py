from ngram import NGram

def get_string_similarity(standard, target):  # input json path string 1, 2
    '''
    문자열을 넣어주면 비교해서 얼마나 같은지 점수로 반환해주는 함수
    :param standard: stand string value for compare
    :param target: target string value for compare
    :return: result : dictionary
            {'1-Gram': reslut, '2-Gram': reslut,  .... '5-Gram': reslut}
    '''
    result = dict()
    # print(f'[+]Stand Binary(length {len(s)}) ::: target Binary(length {len(t)})')

    for i in range(1, 6):
        # print(f"{i}-GRam: {NGram.compare(s, t, N=i)}")
        result.update({str(i) + "-Gram": NGram.compare(standard, target, N=i)})
    return result


def get_func_similarity(s_dict, t_dict, stand_hash_count):
    '''
    해쉬값을 넣어주면 비교해서 얼마나 같은지 점수로 반환해주는 함수
    :param stand_hash_dict: stand value for compare
    :param target_hash_dict: target value for compare
    :return: score callated by comparing True or False statement between standard and target data
    @ 스코어 산출에 target dict은 사용하지 않으나, 일단 가지고 있음.
    '''

    true_count = ([s_dict[fname][fAddr][hashSet] for fname in s_dict for fAddr in s_dict[fname] for hashSet in s_dict[fname][fAddr]]).count(True)
    #print(f'true_count ::: {true_count}')
    #print(f'stand_hash_count ::: {stand_hash_count}')


    return (true_count/stand_hash_count)


def get_data_similarity(self, stand_data, target_data):
    '''
    데이터를 넣어주면 비교해서 얼마나 같은지 점수로 반환해주는 함수 - ssdeep/sdhash/tlsh 사용 예정
    :param stand_data: standard data value for compare
    :param target_data: target data value for compare
    :return: score calculated by comparing between standard and target data
    '''
    cmp_data_score = 0
    return cmp_data_score

    '''
    print('기준!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
    for i in stand_hash_list:
        print(f'key :: {i}, value :: {stand_hash_list[i]} ')

    print('')
    print('')
    print('')

    print('비교대상!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
    for i in target_hash_list:
        print(f'key :: {i}, value :: {target_hash_list[i]} ')

    '''


# if __name__ == "__main__":
#
#     s = timeit.default_timer() # start time
#
#     # Testing code
#     PATH_1 = r"D:\out_idb\test_01.txt"


# if __name__ == "__main__":
#     # s = timeit.default_timer() # start time
#
#     # Testing code
#     PATH_1 = r"D:\out_idb\test_01.txt"
#     PATH_2 = r"D:\out_idb\test_02.txt"
#     gram_result = get_similarity(PATH_1, PATH_2)
#     print(gram_result)
#
#     # print(f"[+]running : {timeit.default_timer() - s}") # end time
