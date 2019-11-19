import hashlib
import filetype
import numpy as np
import ssdeep
import magic
import os
import math

import pefile
from Main_engine.Extract_Engine.PE_feature import pe_pdb, pe_rsrc, pe_rich
from Main_engine.models import PE_info

HEX_M_32 = 0x14c
HEX_M_64_IA = 0x200
HEX_M_64_AMD = 0x8664

class Pe_Feature:
    def __init__(self, file_name, pe):
        self.file_name = file_name
        self.pe = pe

    def extract_time(self):
        time = pe_rsrc.RsrcParser(self.file_name)
        return time.get_timestamp()


    def extract_pdb(self):
        PDB_result = pe_pdb.result_all(self.file_name)
        return PDB_result


    def extract_rsrc(self):

        rsrc = pe_rsrc.RsrcParser(self.file_name)
        rsrc_result, rs, rl = rsrc.get_resource()
        return rsrc_result, rs, rl


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


    def cmp_section_data(self):

        rsrc = pe_rsrc.RsrcParser(self.file_name)
        return rsrc.extract_sections_privileges()


    def Certificateinfo(self):

        rsrc = pe_rsrc.RsrcParser(self.file_name)
        #authentication = rsrc.extractPKCS7()
        return rsrc.extractPKCS7()


    def ImportDll(self):
        '''
        함수 목록에 대해서 모두 리스트로 추출
        ngram으로 유사도 비교 가능
        '''
        ImportDlldict = {}

        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            importlists = []
            for imp in entry.imports:
                try:
                    importlists.append(imp.name.decode())                           # convert function name into string type and append into importlists
                except:
                    continue
            # importlists에 있는 값들을 ImportDlldict에 각각의 .dll(함수)에 추가
            ImportDlldict[entry.dll.decode()] = importlists                         #append values of importlists to ImportDlldict

        return ImportDlldict

    def extract_rich(self):
        rich = pe_rich.ParseRichHeader(self.file_name)
        rich_dict = dict()
        try:
            flag = rich.parse()

            if flag != False:
                xor_key = rich.xorkey
                #rich_dict = dict()
                prod_list = list()
                #print(f'XorKey : {xor_key}')
                #print("ProID    name              count")
                rich_dict['xor key'] = xor_key
                for key in rich.info_list.keys():
                    count = rich.info_list[key]
                    mcv = (key << 16)
                    prodid = (key >> 16)
                    prod_list.append(prodid)
                    prodid_name = pe_rich.PRODID_MAP[prodid] if prodid in pe_rich.PRODID_MAP else "<unknown>"
                    #print('%6d   %-15s %5d     %6d' % (prodid, prodid_name, count, mcv))
                    rich_dict[prodid_name] = count

                return xor_key, prod_list ,rich_dict
            else:
                return "", ""
        except:
            return "", ""

    def filetypes(self):
        '''
        파일타입 추출
        '.'을 기준으로 오른 쪽에 있는 것을 파일 타입으로 kind 변수에 저장
        extension = 파일 타입, mime = 클라이언트에게 전송된 문서의 다양성을 알려주기 위한 메커니즘
        '''
        kind = filetype.guess(self.file_name)
        if kind is None:
            return np.nan
        else:
            if kind.extension == 'exe':
                file_type = 'Window exe'
            else:
                return np.nan
        return file_type

    def convert_size(self, size_bytes):
        if size_bytes == 0:
            return "0B"
        size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        Size = str(s) + size_name[i] + " (" + str(size_bytes) + " bytes)"
        return Size

    def all(self, ):
        func_list = self.ImportDll()
        file_type = magic.from_file(self.file_name)
        imphash = self.imphash_data()
        implist = self.ImportDll()
        cmp_section_data = self.cmp_section_data()
        cert = self.Certificateinfo()
        rich_xor_key, rich_prodid, rich_dict = self.extract_rich()
        pdb_info = self.extract_pdb()
        rsrc_info, rs, rl = self.extract_rsrc()
        time_info, TimeInNum = self.extract_time()

        f_name = self.file_name[self.file_name.rfind('\\') + 1:]

        pe_features = {
            'file_name': f_name,
            'file_hash': hashlib.sha256(open(self.file_name, 'rb').read()).hexdigest(),
            'imp_hash': imphash,
            'Imports': implist,
            'cmp_section': cmp_section_data,
            'auto': cert,
            'rich_xor_key': rich_xor_key,
            'rich_prodid': rich_prodid,
            'rich header': rich_dict,
            'pdb_info': pdb_info,
            'time_date_stamp': time_info,
            'time in num': TimeInNum,
            'rsrc_info': rsrc_info,
            'rsrc_count': rs,
            'rsrc_lang': rl
        }
        file_size = os.path.getsize(self.file_name)
        file_size = self.convert_size(file_size)
        MD5 = hashlib.md5(open(self.file_name, 'rb').read()).hexdigest().upper()
        sha1 = hashlib.sha1(open(self.file_name, 'rb').read()).hexdigest()
        sha256 = hashlib.sha256(open(self.file_name, 'rb').read()).hexdigest()
        ImpHash = imphash.upper()
        ssdeep_hash = ssdeep.hash_from_file(self.file_name)
        TimeStamp = time_info
        PDB = pdb_info
        Cert = cert

        Year = TimeStamp[TimeStamp.rfind('UTC') - 5:TimeStamp.rfind('UTC') - 1]


        pe_features_for_DB = {
            'file name': f_name,
            'file size': file_size,
            'file_type': file_type,
            'MD5 hash': MD5,
            'SHA-1 hash': sha1,
            'SHA-256 hash': sha256,
            'Imp hash': ImpHash,
            'SSDEEP hash': ssdeep_hash,
            'File Creation Time': TimeStamp,
            'PDB Information': PDB,
            'File Certification': Cert
        }

        machine_bit = self.pe.FILE_HEADER.Machine
        mac = ""
        if machine_bit == HEX_M_32:
            mac = "Intel 386 or later processors and compatible processors"
        elif machine_bit == HEX_M_64_AMD or machine_bit == HEX_M_64_IA:
            mac = "x64"
        Ent_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        Section_num = self.pe.FILE_HEADER.NumberOfSections

        pe_header = {
            'Target Machine': mac,
            'File Creation Time': TimeStamp,
            'Enrty Point': Ent_point,
            'Contained Sections': Section_num
        }
        print(pe_header)
        pdb_name = PDB['pe_pdb_Name']
        pdb_guid = PDB['pe_pdb_GUID']
        pdb_age = PDB['pe_pdb_Age']
        pdb_path = PDB['pe_pdb_Pdbpath']

        # print(f"timenum : {type(TimeInNum)}::{TimeInNum}")
        # print(f"EntryPoint : {type(Ent_point)}::{Ent_point}")
        # print(f"ContainedSections : {type(Section_num)}::{Section_num}")
        # print(f"pdbage : {type(pdb_age)}::{pdb_age}")

        PE_info.objects.create(filename=f_name, imphash=ImpHash, filesize=file_size, filetype=file_type, sha_256=sha256,
                               timestamp=TimeStamp, year=Year, timenum=TimeInNum,
                               ssdeep=ssdeep_hash, sha_1=sha1, md5=MD5, Targetmachine=mac, EntryPoint=Ent_point,
                               ContainedSections=Section_num, pdbname=pdb_name, pdbguid=pdb_guid, pdbage=pdb_age, pdbpath=pdb_path)

        return pe_features, pe_features_for_DB

# if __name__ == "__main__":
#     pe = Pe_Feature(r"C:\malware\mid_GandCrab_exe\test")