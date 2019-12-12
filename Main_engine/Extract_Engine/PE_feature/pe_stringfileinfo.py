import pefile
import json

def getFileProperties(fname):
    pe = pefile.PE(fname)
    pe_string = {
        "Comments": "-",
        "InternalName": "-",
        "ProductName": "-",
        "CompanyName": "-",
        "LegalCopyright": "-",
        "ProductVersion": "-",
        "FileDescription": "-",
        "LegalTrademarks": "-",
        "PrivateBuild": "-",
        "FileVersion": "-",
        "OriginalFilename": "-",
        "SpecialBuild": "-"
    }
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
                                pe_string[entry[0].decode()] = "-"
    except:
        pass

    #copyright 특수문자 예외처리
    se = r'\u24d2'
    for k in pe_string.keys():
        pe_string[k] = pe_string[k].replace(se.encode().decode('unicode-escape'), "&#9426;")

    # register 특수문자 예외처리
    reg = r'\u00ae'
    for k in pe_string.keys():
        pe_string[k] = pe_string[k].replace(reg.encode().decode('unicode-escape'), "&#reg;")

    #print(json.dumps(pe_string, indent=4))
    return pe_string