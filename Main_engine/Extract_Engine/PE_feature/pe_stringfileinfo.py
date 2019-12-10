import pefile
import json

def getFileProperties(fname):
    pe = pefile.PE(fname)
    pe_string = dict()
    # print(pe.VS_FIXEDFILEINFO)

    try:
        for fileinfo in pe.FileInfo:
            # print(fileinfo)
            for i in fileinfo:
                if i.Key.decode() == 'StringFileInfo':
                    # print(i)
                    for st in i.StringTable:
                        # print(st)
                        for entry in st.entries.items():
                            pe_string[entry[0].decode()] = entry[1].decode()
                            if "TODO" in entry[1].decode():
                                pe_string[entry[0].decode()] = "No Data"
                            # print(f"{entry[0].decode()}: {entry[1].decode()}")
    except:
        pass

    se = r'\u24d2'
    # print(se.encode().decode('unicode-escape'))
    for k in pe_string.keys():
        # re = pe_string[k].find(se.encode().decode('unicode-escape'))
        # print(re)
        pe_string[k] = pe_string[k].replace(se.encode().decode('unicode-escape'), "")

    print(json.dumps(pe_string, indent=4))
    return pe_string