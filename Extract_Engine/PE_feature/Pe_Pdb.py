import pefile
import numpy as np
import struct

class PDB_analyze():
    def __init__(self, filename):
        self.filename = filename
        self.pe = pefile.PE(self.filename)

    def run(self, pe_info_json):

        pdb_data = self.pdb_data()  #
        pe_info_json['pe_pdb_Name'] = pdb_data['Name']
        pe_info_json['pe_pdb_GUID'] = pdb_data['GUID']  # pdb(컴파일된 정보 중 하나)컴파일된 환경(프로젝트)의 아이디
        pe_info_json['pe_pdb_Age'] = pdb_data['Age']  # 코드의 빌드 횟수
        pe_info_json['pe_pdb_pdbPath'] = pdb_data['Pdbpath']  # 중요***      pdb파일이 있는 경로

        self.pe.close()
        return pe_info_json

    def pdb_data(self):  # pdb 추출하는 함수
        if hasattr(self.pe, u"DIRECTORY_ENTRY_DEBUG"):
            for i in self.pe.DIRECTORY_ENTRY_DEBUG:
                entry = i.entry
                #PDB 필드의 signature 값이 RSDS인 것들만
                if hasattr(entry, "CvSignature"):  # RSDS
                    name = entry.name
                    ###
                    #GUID(컴파일된 환경의 아이디) 정보를 바이트형으로 패킹한 후
                    guid_data1 = struct.pack('<I', entry.Signature_Data1)
                    guid_data2 = struct.pack('<H', entry.Signature_Data2)
                    guid_data3 = struct.pack('<H', entry.Signature_Data3)
                    #little엔디안으로 int형으로 바꿈
                    GUID = "%x-%x-%x-%x".upper() % (int.from_bytes(guid_data1, "little"),
                                                    int.from_bytes(guid_data2, "little"),
                                                    int.from_bytes(guid_data3, "little"),
                                                    int.from_bytes(entry.Signature_Data4, "little")
                                                    )
                    Age = entry.Age

                    return {"Name": name, "GUID": GUID, "Age": Age, "Pdbpath": entry.PdbFileName.decode()}

                elif hasattr(entry, "CvHeaderSignature"):  # NB10
                    name = entry.name
                    GUID = hex(entry.Signature)
                    Age = entry.Age
                    Pdbpath = entry.PdbFileName.decode()
                    return {"Name": name, "GUID": GUID, "Age": Age, "Pdbpath": Pdbpath}

                else:
                    return {"Name": np.nan, "GUID": np.nan, "Age": np.nan, "Pdbpath": np.nan}
        else:
            return {"Name": np.nan, "GUID": np.nan, "Age": np.nan, "Pdbpath": np.nan}

def result_all(filename, output_data):
    pe_anal = PDB_analyze(filename)
    output_data = pe_anal.run(output_data)
    print("NamHoon Git Test05")
    return output_data