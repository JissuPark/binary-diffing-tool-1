import pefile
import json

def getFileProperties(fname):
    pe = pefile.PE(fname)
    pe_string = dict()
    # print(pe.VS_FIXEDFILEINFO)

    try:
        for fileinfo in pe.FileInfo:
            for i in fileinfo:
                if i.Key.decode() == 'StringFileInfo':
                    for st in i.StringTable:
                        for entry in st.entries.items():
                            pe_string[entry[0].decode()] = entry[1].decode()
                            if "TODO" in entry[1].decode():
                                #print(entry[0].encode("ascii",'backslashreplace'), ":", entry[0].encode("ascii",'backslashreplace'))
                                pe_string[entry[0].decode()] = "No Data"
    except:
        pass

    se = r'\u24d2'
    for k in pe_string.keys():

        pe_string[k] = pe_string[k].replace(se.encode().decode('unicode-escape'), "&#9426;")

    #print(json.dumps(pe_string, indent=4))
    return pe_string