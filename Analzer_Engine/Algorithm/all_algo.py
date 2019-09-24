from ngram import NGram


def get_similarity(standard, target):  # input json path string 1, 2
    reslut = dict()
    # print(f'[+]Stand Binary(length {len(s)}) ::: target Binary(length {len(t)})')

    for i in range(1, 6):
        # print(f"{i}-GRam: {NGram.compare(s, t, N=i)}")
        reslut.update({str(i) + "-Gram": NGram.compare(standard, target, N=i)})
    return reslut
    '''
        return reslut type : dict
        {'1-Gram': reslut, '2-Gram': reslut,  .... '5-Gram': reslut}

    '''
def get_func_similarity(stand_hash_dict, target_hash_dict):

    for i in stand_hash_dict:
        for j in stand_hash_dict:
            if i == j:
                target_hash_dict[j] = True
                target_hash_dict[i] = True
            else:
                pass

    return (list((stand_hash_dict.values())).count(True)/len(stand_hash_dict))


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
