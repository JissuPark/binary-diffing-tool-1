import hashlib
import filetype
import numpy as np

import pefile
from Main_engine.Extract_Engine.PE_feature import pe_pdb, pe_rsrc, pe_rich


class Pe_Feature:
    def __init__(self, file_name):
        self.file_name = file_name
        self.pe = pefile.PE(self.file_name)

    def extract_time(self):
        time = pe_rsrc.RsrcParser(self.file_name)
        return time.get_timestamp()

    def extract_rich(self):
        rich = pe_rich.ParseRichHeader(self.file_name)
        flag = rich.parse()

        if flag != False:
            xor_key = rich.xorkey
            rich_dict = dict()
            print(f'XorKey : {xor_key}')
            print("ProID    name              count")
            for key in rich.info_list.keys():
                count = rich.info_list[key]
                mcv = (key << 16)
                prodid = (key >> 16)

                prodid_name = pe_rich.PRODID_MAP[prodid] if prodid in pe_rich.PRODID_MAP else "<unknown>"
                print('%6d   %-15s %5d     %6d' % (prodid, prodid_name, count, mcv))
                rich_dict[key] = count

            return xor_key
        else:
            return ""

    def extract_pdb(self):
        output_data = dict()
        PDB_result = pe_pdb.result_all(self.file_name)
        return PDB_result

    def extract_rsrc(self):
        rsrc = pe_rsrc.RsrcParser(self.file_name)
        rsrc_result = rsrc.get_resource()
        return rsrc_result
    def ex_auth(self):
        au = pe_rsrc.RsrcParser(self.file_name)
        return au.section_auth()

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

    def cmp_section_data(self):
        rsrc = pe_rsrc.RsrcParser(self.file_name)
        return rsrc.extract_sections_privileges()

    def Autoninfo(self):
        rsrc = pe_rsrc.RsrcParser(self.file_name)
        #authentication = rsrc.extractPKCS7()
        return rsrc.extractPKCS7()

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

    def all(self):
        test= dict()
        func_list = self.ImportDll()
        #file_type = self.filetypes()
        imphash = self.imphash_data()
        cmp_section_data = self.cmp_section_data()
        auto = self.Autoninfo()
        rich_info = self.extract_rich()
        pdb_info = self.extract_pdb()
        rsrc_info = self.extract_rsrc()
        time_info = self.extract_time()

        pe_features = {
            'file_name': self.file_name[28:],
            'file_hash': hashlib.sha256(open(self.file_name, 'rb').read()).hexdigest(),
            'imp_hash': imphash,
            'cmp_section': cmp_section_data,
            'auto': auto,
            'rich_info': rich_info,
            'pdb_info': pdb_info,
            'time_date_stamp': time_info
            #'rsrc_info': rsrc_info
        }


        return pe_features

if __name__ == "__main__":
    pe = Pe_Feature(r"C:\malware\mid_GandCrab_exe\test")