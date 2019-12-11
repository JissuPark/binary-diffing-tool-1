#-*- coding: utf-8 -*-
import pefile
import sys
import re
import math

mutex_file=open('mutex_strings_lists.txt','r')
mutex_list = [line[:-1] for line in mutex_file]

mutex_file2=open('win32api_alphabet.txt','r')
mutex_list2 = [line2[:-1] for line2 in mutex_file2]

mutex_file3=open('win32api_category.txt','r')
mutex_list3 = [line3[:-1] for line3 in mutex_file3]

    
def exstrings(FILENAME,regex=None):
    importlists = []
    try:
        PF=pefile.PE(FILENAME)


        for entry in PF.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                importlists.append(imp.name.decode())
        PF.close()
    except:
        pass

    
    EXSTRINGS_RESULT_LIST=[]
    fp=open(FILENAME,'rb')
    bindata = str(fp.read())
    if regex is None:
        regex = re.compile("[\w\~\!\@\#\$\%\^\&\*\(\)\-_=\+ \/\.\,\?\s]{4,}")
        
        BINDATA_RESULT = regex.findall(bindata)
    else:
        regex = re.compile(regex)
    for BINDATA in BINDATA_RESULT:
        if len(BINDATA)>3000:
            continue
        try:
            regex2=re.compile('([x\d]+)|([\D]+)')
            
            BINDATA_REGEX2=regex2.search(BINDATA)
            if BINDATA_REGEX2.group(1)==None:
                if len(BINDATA_REGEX2.group(2))>6:
                    if BINDATA_REGEX2.group(2) in importlists or BINDATA_REGEX2.group(2)[:-1] in importlists:
                        continue
                    elif BINDATA_REGEX2.group(2)  in mutex_list or BINDATA_REGEX2.group(2)[:-1] in mutex_list:
                        continue
                    elif BINDATA_REGEX2.group(2)  in mutex_list2 or BINDATA_REGEX2.group(2)[:-1] in mutex_list2:
                        continue
                    elif BINDATA_REGEX2.group(2)  in mutex_list3 or BINDATA_REGEX2.group(2)[:-1] in mutex_list3:
                        continue
                    EXSTRINGS_RESULT_LIST.append(BINDATA_REGEX2.group(2))
            elif BINDATA_REGEX2.group(1)!=None:
                regex2=re.compile('([x\d]+)([\D]+)')
                BINDATA_REGEX2=regex2.search(BINDATA)
                if len(BINDATA_REGEX2.group(2))>6:
                    if BINDATA_REGEX2.group(2) in importlists or BINDATA_REGEX2.group(2)[:-1] in importlists:
                        continue
                    elif BINDATA_REGEX2.group(2)  in mutex_list or BINDATA_REGEX2.group(2)[:-1] in mutex_list:
                        continue
                    elif BINDATA_REGEX2.group(2)  in mutex_list2 or BINDATA_REGEX2.group(2)[:-1] in mutex_list2:
                        continue
                    elif BINDATA_REGEX2.group(2)  in mutex_list3 or BINDATA_REGEX2.group(2)[:-1] in mutex_list3:
                        continue
                    EXSTRINGS_RESULT_LIST.append(BINDATA_REGEX2.group(2))
        except:
            continue
    fp.close()
    return EXSTRINGS_RESULT_LIST


def getEntropy(FILENAME):
    ENTROPY_LIST={}
    PF=pefile.PE(FILENAME)
    for PE_SECTION in PF.sections:
        data = PE_SECTION.get_data()
        occurences = pefile.Counter(bytearray(data))
        entropy = 0
        for x in occurences.values():
            p_x = float(x) / len(data)
            entropy -= p_x*math.log(p_x, 2)
            

        try:
            
            ENTROPY_LIST[PE_SECTION.Name.decode().replace('\x00','')]=entropy
        except:
            
            ENTROPY_LIST

    PF.close()
    return ENTROPY_LIST


        

if __name__=="__main__":
    sample_path = "D:\\Allinone\\BOB\\Python\\Tensflow\\samples\\mal_samples\\Bluenoroff\\f2a139dd99a504c9a36aafda8dc58e041f86b4e975af796b07cc84e2ebd8d4f6"
    print(getEntropy(sample_path))
