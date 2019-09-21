import json
import filetype
import numpy as np

import pefile
from Extract_Engine.PE_feature import Pe_Rich, Pe_Rsrc, Pe_Pdb


class Pe_Features:
    def __init__(self, file_name):
        self.file_name = file_name
        self.pe=pefile.PE(self.file_name)

    def extract_rich(self):
        rich = Pe_Rich.ParseRichHeader(self.file_name)
        xor_key = rich.xorkey

        print(f'XorKey : {xor_key}')
        print("ProID    name              count")
        for key in rich.info_list.keys():
            count = rich.info_list[key]
            prodid = (key >> 16)
            prodid_name = Pe_Rich.PRODID_MAP[prodid] if prodid in Pe_Rich.PRODID_MAP else "<unknown>"
            # print('%6d   %-15s %5d' % (prodid, prodid_name, count))

        return json.dumps(rich.info_list, indent=4)

    def extract_pdb(self):
        output_data = {}
        PDB_result = Pe_Pdb.result_all(self.file_name, output_data)
        return json.dumps(PDB_result, indent=4)

    def extract_rsrc(self):
        rsrc = Pe_Rsrc.RsrcParser(self.file_name)
        rsrc.get_resource()
        return json.dumps(rsrc.resource, indent=4)

    def imphash_data(self):
        '''
        imphash : import table의 모든 함수 목록을 하나의 해쉬로
        get_imphash()함수 : 함수 이름(.dll)을 찾아서 md5해시 후 리턴
        '''

        if self.pe.get_imphash().upper() == "":
            return np.nan
        return self.pe.get_imphash().upper()

    def filetypes(self):
        '''
        파일타입 추출
        '.'을 기준으로 오른 쪽에 있는 것을 파일 타입으로 kind 변수에 저장
        extension = 파일 타입, mime = 클라이언트에게 전송된 문서의 다양성을 알려주기 위한 메커니즘
        '''
        kind = filetype.guess(self.file_name)
        if kind is None:
            return np.nan
        return {kind.extension: kind.mime}

    def Sectioninfo(self):  # section별 데이터의 해시화
        sections_dict = {}
        for sections in self.pe.sections:
            try:
                # change meaningless parts like '\x00' into empty char
                sections_dict[sections.Name.decode().replace("\x00", "")] = [sections.get_hash_sha256(),
                                                                             hex(sections.PointerToRawData)]
            except:
                sname = sections.Name.decode('latin-1').encode('utf-8').decode('utf-8').replace('\x00', '')
                sname = list(sname)
                # if name doesn't start with '.' then delete that part
                if sname[0] != '.':
                    del (sname[0])
                # if name start with '.' then return sah256 hash value and section's start address
                sections_dict[''.join(sname)] = [sections.get_hash_sha256(), hex(sections.PointerToRawData)]

        return sections_dict

    def Autoninfo(self):
        rsrc = Pe_Rsrc.RsrcParser(self.file_name)
        authentication = rsrc.extractPKCS7()
        return json.dumps(authentication, indent=4)

    def ImportDll(self):
        '''
        함수 목록에 대해서 모두 리스트로 추출
        ngram으로 유사도 비교 가능
        '''
        ImportDlldict = {}
        try:
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                importlists = []
                for imp in entry.imports:
                    try:
                        importlists.append(imp.name.decode())                           # convert function name into string type and append into importlists
                    except:
                        continue
                # importlists에 있는 값들을 ImportDlldict에 각각의 .dll(함수)에 추가
                ImportDlldict[entry.dll.decode()] = importlists                         #append values of importlists to ImportDlldict
        except:
            return np.nan
        return ImportDlldict


if __name__ == "__main__":
    PATH = r"D:\JungJaeho\STUDY\self\BOB\BoB_Project\Team_Breakers\Training\Study\sample\mid_GandCrab_exe\2cb5cfdc436638575323eac73ed36acd84b4694c144a754772c67167b99d574c"

    ppe = Pe_Features(PATH)
    func_list = ppe.ImportDll()
    imphash = ppe.imphash_data()
    section = ppe.Sectioninfo()
    auto = ppe.Autoninfo()

    print("filetype  :: ", ppe.filetypes())
    print("function list :: ", json.dumps(func_list, indent=4))
    print("imphash_data :: ", imphash)
    print("section hash :: ", json.dumps(section, indent=4))
    print("authentication data :: ", auto)

    print(f'pe rich header info : {ppe.extract_rich()}')
    print(f'pe pdb  header info : {ppe.extract_pdb()}')
    print(f'pe resource info : {ppe.extract_rsrc()}')


