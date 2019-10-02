import pefile
import numpy as np
import struct

class PDB_analyze():
    def __init__(self, filename):
        self.filename = filename
        self.pe = pefile.PE(self.filename)

    def pdb_data(self):  # pdb 추출하는 함수
        PDB_dict = dict()
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
                    guid_data4 = struct.pack('<8s', entry.Signature_Data4)
                    #little엔디안으로 int형으로 바꿈
                    GUID = "%x-%x-%x-%x".upper() % (int.from_bytes(guid_data1, "little"),
                                                    int.from_bytes(guid_data2, "little"),
                                                    int.from_bytes(guid_data3, "little"),
                                                    int.from_bytes(guid_data4, "little")
                                                    )
                    Age = entry.Age
                    Pdbpath = entry.PdbFileName.decode().replace("\u0000", "")
                    PDB_dict["pe_pdb_Name"] = name
                    PDB_dict["pe_pdb_GUID"] = GUID
                    PDB_dict["pe_pdb_Age"] = Age
                    PDB_dict["pe_pdb_Pdbpath"] = Pdbpath
                    self.pe.close()
                    return PDB_dict

                elif hasattr(entry, "CvHeaderSignature"):  # NB10
                    name = entry.name
                    GUID = hex(entry.Signature)
                    Age = entry.Age
                    Pdbpath = entry.PdbFileName.decode().replace("\u0000", "")
                    PDB_dict["pe_pdb_Name"] = name
                    PDB_dict["pe_pdb_GUID"] = GUID
                    PDB_dict["pe_pdb_Age"] = Age
                    PDB_dict["pe_pdb_Pdbpath"] = Pdbpath
                    self.pe.close()
                    return PDB_dict

                else:
                    PDB_dict["pe_pdb_Name"] = np.nan
                    PDB_dict["pe_pdb_GUID"] = np.nan
                    PDB_dict["pe_pdb_Age"] = np.nan
                    PDB_dict["pe_pdb_Pdbpath"] = np.nan
                    self.pe.close()
                    return PDB_dict
        else:
            PDB_dict["pe_pdb_Name"] = np.nan
            PDB_dict["pe_pdb_GUID"] = np.nan
            PDB_dict["pe_pdb_Age"] = np.nan
            PDB_dict["pe_pdb_Pdbpath"] = np.nan
            self.pe.close()
            return PDB_dict

def result_all(filename):
    pe_anal = PDB_analyze(filename)
    output_data = pe_anal.pdb_data()
    return output_data