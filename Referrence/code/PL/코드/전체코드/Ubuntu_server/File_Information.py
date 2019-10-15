try:
    import hashlib
    import operator as op
    import binascii
except:
    print("IMPORT ERROR")

    
class STRINGS:
    def __init__(self):
        self.VECTOR='0x4a5b6c7d8f9a'
        self.blocksize=65536
        
    def getHash(self,path):
        self.path=path
        self.afile = open(self.path, 'rb')
        self.hasher = hashlib.sha256()
        self.buf = self.afile.read(self.blocksize)
        while len(self.buf) > 0:
            self.hasher.update(self.buf)
            self.buf = self.afile.read(self.blocksize)
        self.afile.close()
        return self.hasher.hexdigest()

    def STR_HEX_COVERTER(self,STRINGS):
        self.HEX_TEMP_VERB=''
        self.STRINGS=STRINGS
        self.STRINGS=binascii.hexlify(self.STRINGS.encode())
        self.STRINGS='0x'+self.STRINGS.decode()
        return self.STRINGS

    def STR_XOR(self,STRINGS_LISTS):
        self.STRINGS_LISTS=STRINGS_LISTS
        self.STRINGS_LISTS_LENGTH=len(self.STRINGS_LISTS)
        for self.STRINGS_LISTS_LENGTH_INDEX in range(0,self.STRINGS_LISTS_LENGTH):
            if self.STRINGS_LISTS_LENGTH_INDEX==0:
                self.STRINGS=int(self.STRINGS_LISTS[self.STRINGS_LISTS_LENGTH_INDEX],16)
                self.STRINGS=op.xor(int(self.VECTOR,16),self.STRINGS)
                #print("VECTOR : {}\n".format(hex(self.STRINGS)))
                continue

            self.STRINGS=op.xor(self.STRINGS,int(self.STRINGS_LISTS[self.STRINGS_LISTS_LENGTH_INDEX],16))
            #print(hex(self.STRINGS))
        return self.STRINGS

    def STR_ADD(self,STRINGS_LISTS):
        
        STRINGS_LISTS_LENGTH=len(STRINGS_LISTS)
        for STRINGS_LISTS_LENGTH_INDEX in range(0,STRINGS_LISTS_LENGTH):
            if STRINGS_LISTS_LENGTH_INDEX==0:
                STRINGS=int(STRINGS_LISTS[STRINGS_LISTS_LENGTH_INDEX],16)
                #self.STRINGS=op.xor(int(self.VECTOR,16),self.STRINGS)
                #print("\n\tVECTOR : {}\n".format(hex(self.STRINGS)))
                continue

            STRINGS=op.add(STRINGS,int(STRINGS_LISTS[STRINGS_LISTS_LENGTH_INDEX],16))
            #print("\t\tADD Value : {}".format(hex(self.STRINGS)))
        return STRINGS
    
if __name__=="__main__":
    st=STRINGS()
    a='push  mov  mov  push  call  esp'
    print(a)
    
    a=a.split('  ')
    for b in a:
        
        print(st.STR_HEX_COVERTER(b))