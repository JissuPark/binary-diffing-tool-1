


import json
import re
import timeit

def read_json(PATH):

    with open(PATH, "r") as json_file:
        json_data = json.load(json_file)

    return json_data

def fileter_split(block_constant):
    stand = re.compile('0x[0-9a-f]{2}| 0x[0-9a-f]{4}| 0x[0-9a-f]{8}')
    split_const = block_constant.split()
    filter_const = list()
    strings = list()

    for i in split_const:
        if (len(i) == 4 or len(i) == 10 or len(i) == 6) and stand.match(i):
        #if stand.match(i):
            filter_const.append(i)

    if filter_const and len(filter_const) > 4:
        #print(filter_const)
        for x in filter_const:
            if len(x) == 10:
                a = (x.split('0x')[1:])
                y1 = '0x'+(a[0][:2])
                y2 = '0x'+(a[0][2:4])
                y3 = '0x'+(a[0][4:6])
                y4 = '0x'+(a[0][6:8])
                y = list()
                y.append(y1)
                y.append(y2)
                y.append(y3)
                y.append(y4)
                #print(y)
                test = [chr(int(q, 16)) for q in y]
                print(*(test[::-1]))
            elif len(x) == 6:
                a = (x.split('0x')[1:])
                y1 = '0x'+(a[0][:2])
                y2 = '0x'+(a[0][2:4])
                y = list()
                y.append(y1)
                y.append(y2)
                test = [chr(int(q, 16)) for q in y]
                print(*(test[::-1]))
            else:
                strings.append(chr(int(x, 16)))
        print(''.join(strings))


def const_to_ascii(PATH):

    json_data = read_json(PATH)

    func_list = [x for x in json_data if 'constant' != x]
    Bblock_list = list()

    for x in func_list:
        func_list_BB = list(json_data[x].keys())
        Bblock_list.append(func_list_BB[:-1]) 
        
    for i in range(0, len(func_list)):
        for j in Bblock_list[i]:
            block_constant = json_data[func_list[i]][j]["block_constant"]
            if block_constant:
                fileter_split(block_constant)


if __name__ == "__main__":
    s = timeit.default_timer()

    #PATH_1 = r"D:\out_idb\0505.txt"
    PATH_1 = r"D:\out_idb\oeo10.txt"
    const_to_ascii(PATH_1)    

    print(f'[+]running : {timeit.default_timer() - s}')
