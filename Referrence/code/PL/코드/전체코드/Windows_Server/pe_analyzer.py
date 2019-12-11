import pefile
import csv
import hashlib
import sys
import os
import OpenSSL
import binary_checker
import Str_Ent
import itertools
import copy
import pe_charateristics as characteristics
import filetype
import struct
import json
import signal

PRODID_MAP = {
  0: "Unknown",
  1: "Import0",
  2: "Linker510",
  3: "Cvtomf510",
  4: "Linker600",
  5: "Cvtomf600",
  6: "Cvtres500",
  7: "Utc11_Basic",
  8: "Utc11_C",
  9: "Utc12_Basic",
  10: "Utc12_C",
  11: "Utc12_CPP",
  12: "AliasObj60",
  13: "VisualBasic60",
  14: "Masm613",
  15: "Masm710",
  16: "Linker511",
  17: "Cvtomf511",
  18: "Masm614",
  19: "Linker512",
  20: "Cvtomf512",
  21: "Utc12_C_Std",
  22: "Utc12_CPP_Std",
  23: "Utc12_C_Book",
  24: "Utc12_CPP_Book",
  25: "Implib700",
  26: "Cvtomf700",
  27: "Utc13_Basic",
  28: "Utc13_C",
  29: "Utc13_CPP",
  30: "Linker610",
  31: "Cvtomf610",
  32: "Linker601",
  33: "Cvtomf601",
  34: "Utc12_1_Basic",
  35: "Utc12_1_C",
  36: "Utc12_1_CPP",
  37: "Linker620",
  38: "Cvtomf620",
  39: "AliasObj70",
  40: "Linker621",
  41: "Cvtomf621",
  42: "Masm615",
  43: "Utc13_LTCG_C",
  44: "Utc13_LTCG_CPP",
  45: "Masm620",
  46: "ILAsm100",
  47: "Utc12_2_Basic",
  48: "Utc12_2_C",
  49: "Utc12_2_CPP",
  50: "Utc12_2_C_Std",
  51: "Utc12_2_CPP_Std",
  52: "Utc12_2_C_Book",
  53: "Utc12_2_CPP_Book",
  54: "Implib622",
  55: "Cvtomf622",
  56: "Cvtres501",
  57: "Utc13_C_Std",
  58: "Utc13_CPP_Std",
  59: "Cvtpgd1300",
  60: "Linker622",
  61: "Linker700",
  62: "Export622",
  63: "Export700",
  64: "Masm700",
  65: "Utc13_POGO_I_C",
  66: "Utc13_POGO_I_CPP",
  67: "Utc13_POGO_O_C",
  68: "Utc13_POGO_O_CPP",
  69: "Cvtres700",
  70: "Cvtres710p",
  71: "Linker710p",
  72: "Cvtomf710p",
  73: "Export710p",
  74: "Implib710p",
  75: "Masm710p",
  76: "Utc1310p_C",
  77: "Utc1310p_CPP",
  78: "Utc1310p_C_Std",
  79: "Utc1310p_CPP_Std",
  80: "Utc1310p_LTCG_C",
  81: "Utc1310p_LTCG_CPP",
  82: "Utc1310p_POGO_I_C",
  83: "Utc1310p_POGO_I_CPP",
  84: "Utc1310p_POGO_O_C",
  85: "Utc1310p_POGO_O_CPP",
  86: "Linker624",
  87: "Cvtomf624",
  88: "Export624",
  89: "Implib624",
  90: "Linker710",
  91: "Cvtomf710",
  92: "Export710",
  93: "Implib710",
  94: "Cvtres710",
  95: "Utc1310_C",
  96: "Utc1310_CPP",
  97: "Utc1310_C_Std",
  98: "Utc1310_CPP_Std",
  99: "Utc1310_LTCG_C",
  100: "Utc1310_LTCG_CPP",
  101: "Utc1310_POGO_I_C",
  102: "Utc1310_POGO_I_CPP",
  103: "Utc1310_POGO_O_C",
  104: "Utc1310_POGO_O_CPP",
  105: "AliasObj710",
  106: "AliasObj710p",
  107: "Cvtpgd1310",
  108: "Cvtpgd1310p",
  109: "Utc1400_C",
  110: "Utc1400_CPP",
  111: "Utc1400_C_Std",
  112: "Utc1400_CPP_Std",
  113: "Utc1400_LTCG_C",
  114: "Utc1400_LTCG_CPP",
  115: "Utc1400_POGO_I_C",
  116: "Utc1400_POGO_I_CPP",
  117: "Utc1400_POGO_O_C",
  118: "Utc1400_POGO_O_CPP",
  119: "Cvtpgd1400",
  120: "Linker800",
  121: "Cvtomf800",
  122: "Export800",
  123: "Implib800",
  124: "Cvtres800",
  125: "Masm800",
  126: "AliasObj800",
  127: "PhoenixPrerelease",
  128: "Utc1400_CVTCIL_C",
  129: "Utc1400_CVTCIL_CPP",
  130: "Utc1400_LTCG_MSIL",
  131: "Utc1500_C",
  132: "Utc1500_CPP",
  133: "Utc1500_C_Std",
  134: "Utc1500_CPP_Std",
  135: "Utc1500_CVTCIL_C",
  136: "Utc1500_CVTCIL_CPP",
  137: "Utc1500_LTCG_C",
  138: "Utc1500_LTCG_CPP",
  139: "Utc1500_LTCG_MSIL",
  140: "Utc1500_POGO_I_C",
  141: "Utc1500_POGO_I_CPP",
  142: "Utc1500_POGO_O_C",
  143: "Utc1500_POGO_O_CPP",

  144: "Cvtpgd1500",
  145: "Linker900",
  146: "Export900",
  147: "Implib900",
  148: "Cvtres900",
  149: "Masm900",
  150: "AliasObj900",
  151: "Resource900",

  152: "AliasObj1000",
  154: "Cvtres1000",
  155: "Export1000",
  156: "Implib1000",
  157: "Linker1000",
  158: "Masm1000",

  170: "Utc1600_C",
  171: "Utc1600_CPP",
  172: "Utc1600_CVTCIL_C",
  173: "Utc1600_CVTCIL_CPP",
  174: "Utc1600_LTCG_C ",
  175: "Utc1600_LTCG_CPP",
  176: "Utc1600_LTCG_MSIL",
  177: "Utc1600_POGO_I_C",
  178: "Utc1600_POGO_I_CPP",
  179: "Utc1600_POGO_O_C",
  180: "Utc1600_POGO_O_CPP",
  
  # vvv
  183: "Linker1010",
  184: "Export1010",
  185: "Implib1010",
  186: "Cvtres1010",
  187: "Masm1010",
  188: "AliasObj1010",
  # ^^^

  199: "AliasObj1100",
  201: "Cvtres1100",
  202: "Export1100",
  203: "Implib1100",
  204: "Linker1100",
  205: "Masm1100",

  206: "Utc1700_C",
  207: "Utc1700_CPP",
  208: "Utc1700_CVTCIL_C",
  209: "Utc1700_CVTCIL_CPP",
  210: "Utc1700_LTCG_C ",
  211: "Utc1700_LTCG_CPP",
  212: "Utc1700_LTCG_MSIL",
  213: "Utc1700_POGO_I_C",
  214: "Utc1700_POGO_I_CPP",
  215: "Utc1700_POGO_O_C",
  216: "Utc1700_POGO_O_CPP",
}


##########################################################################

class richheader:
    def __init__(self, fp):
        self.info = []
        self.clear_data=[]
        self.prodid = []
        self.xorkey = ""
        try:
            data = fp.read()
            end = struct.unpack('<I', data[0x3c:0x40])[0]
            data = data[0x80:end]
            rich_addr = data.find(b'Rich')                                              
            self.xorkey = struct.unpack('<I',data[rich_addr + 4:rich_addr + 8])[0]
            self.data = data[:rich_addr]
            for i in range(16, rich_addr, 8):
                key = struct.unpack("<L", self.data[i:i+4])[0] ^ self.xorkey
                count = struct.unpack("<L", self.data[i+4:i+8])[0] ^ self.xorkey
                info = Info(key, count)
                self.info.append(info)
        except:
            del self.info[:]  
                                                        

    def return_prodid(self):
        set1 = []
        if (len(self.info) != 0):
            for i in self.info:
                set1.append(i.prodid)
        return (set1)
    
    def return_clear_data(self):
        set1 = []
        if (len(self.info) != 0):
            for i in self.info:
                set1.append(hex(i.compid))
                set1.append(hex(i.count))
        return (set1)
    
    def return_build(self):
        set1 = []
        if (len(self.info) != 0):
            for i in self.info:
                set1.append(hex(i.build))
        return (set1)
    
    def return_count(self):
        set1 = []
        if (len(self.info) != 0):
            for i in self.info:
                set1.append(hex(i.count))
        return (set1)


# Extraction result
class Info:
    def __init__(self, compid, count):
        self.compid = compid
        self.prodid = compid >> 16
        self.build = compid & 0xffff
        self.count = count
        
def RichHeader_data(filename):
    RichHeader_dic={'prodid':None,
                    "xorkey":None,
                    "sample_clear_data":None,
                    "build":None,
                    "count":None
                    }
    try:
        open_file=open(filename,'rb')
        sample_rich_information=richheader(open_file)
        xorkey = hex(sample_rich_information.xorkey)
        RichHeader_dic['xorkey']=xorkey

        prodid = sample_rich_information.return_prodid()
        prodid_list =[]
        for i in prodid:
            if (i<=216):
                prodid_list.append(i)
                prodid_list.append(PRODID_MAP[i])
            elif(i>216):
                prodid_list.append(i)
                prodid_list.append(None)
        RichHeader_dic['prodid']=prodid_list

        sample_clear_data=sample_rich_information.return_clear_data()
        RichHeader_dic['sample_clear_data']=sample_clear_data
        build = sample_rich_information.return_build()
        RichHeader_dic['build']=build
        count = sample_rich_information.return_count()
        RichHeader_dic['count']=count
        open_file.close()
    except:
        return None

    return RichHeader_dic
    


class PE_analyzer():
    def __init__(self, filename):
        self.filename = filename
        self.pe = pefile.PE(self.filename)
        ## https://www.checktls.com/showcas.html
        self.blacklist = ["verisign", "symantec","thawte", "microsoft"]
        
    
    def rich_header_data(self):
        rich_header = self.pe.parse_rich_header()
        if rich_header is not None:
            return {"clear_data":hashlib.md5(rich_header['clear_data']).hexdigest().upper(),"xor_key":rich_header['key'].hex().upper()}
        else:
            return {"clear_data":None, "xor_key":None}

    def md5_data(self):
        file_object=open(self.filename,"rb")
        data=file_object.read()
        hash_md5=hashlib.md5(data).hexdigest().upper()
        file_object.close()
        return hash_md5

    def sha256_data(self):
        file_object=open(self.filename,"rb")
        data=file_object.read()
        hash_sha256=hashlib.sha256(data).hexdigest().upper()
        file_object.close()
        return hash_sha256

    def imphash_data(self):
        if self.pe.get_imphash().upper()=="":
            return None
        return self.pe.get_imphash().upper()
    
    def check_decode_pdb(self, string):
        try:
            Pdbpath = string.decode("utf-8").replace("\x00","")
            return Pdbpath
            
        except UnicodeDecodeError:
            print("[*] UnicodeDecodeError UTF-8")

        try:
            Pdbpath = string.decode("euc-kr").replace("\x00","")
            print("[*] Unicode Clear EUC_KR")
            return Pdbpath

        except UnicodeDecodeError:
            print("[*] UnicodeDecodeError EUC_KR")

        try:
            Pdbpath = string.decode("latin-1").replace("\x00","") # Thanks for Dongju
            print("[*] Unicode Clear latin-1")
            return Pdbpath

        except UnicodeDecodeError:
            print("[*] UnicodeDecodeError latin-1")
            Pdbpath = string.replace(b"\x00",b"")

        return Pdbpath
    def pdb_data(self):
        if hasattr(self.pe, u"DIRECTORY_ENTRY_DEBUG"):
            for i in self.pe.DIRECTORY_ENTRY_DEBUG:
                entry = i.entry

                if hasattr(entry, "CvSignature"): # RSDS
                    name = entry.name
                    GUID = "%x-%x-%x-%x-%x%x".upper() % (entry.Signature_Data1, 
                                                        entry.Signature_Data2, 
                                                        entry.Signature_Data3, 
                                                        entry.Signature_Data4, 
                                                        entry.Signature_Data5, entry.Signature_Data6)
                    Age = entry.Age

                    return {"Name":name, "GUID":GUID, "Age":Age, "Pdbpath":self.check_decode_pdb(entry.PdbFileName)}

                elif hasattr(entry, "CvHeaderSignature"): # NB10
                    name = entry.name
                    GUID = hex(entry.Signature)
                    Age = entry.Age
                    Pdbpath = entry.PdbFileName
                    return {"Name":name, "GUID":GUID, "Age":Age, "Pdbpath":self.check_decode_pdb(entry.PdbFileName)}

                else:
                    return {"Name":None, "GUID":None, "Age":None, "Pdbpath":None}
        else:
            return {"Name":None, "GUID":None, "Age":None, "Pdbpath":None}

    def codesign_data(self):
        try:
            security_num = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
            if not self.pe.OPTIONAL_HEADER.DATA_DIRECTORY == [] or len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY) >= 5:
                size = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_num].Size
                va = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_num].VirtualAddress
                if not size == 0 and not va == 0:
                    try:
                        result = []
                        signatures = self.pe.write()[va+8:]
                        pkcs7 = OpenSSL.crypto.load_pkcs7_data(OpenSSL.crypto.FILETYPE_ASN1, bytes(signatures))
                        certs = OpenSSL.crypto.PKCS7.get_certificates(pkcs7)
                    except:
                        return None

                    for cert in certs:
                        subject = cert.get_subject()
                        organization = subject.O
                        if organization is not None and not any(i in organization.lower() for i in self.blacklist):
                            serial_number = "%032x" % cert.get_serial_number()
                            #common_name = subject.CN
                            #country = subject.C
                            #locality = subject.L
                            result.append(serial_number)
                    return ', '.join(result)
                else:
                    return None
            else:
                return None
        except OpenSSL.crypto.Error:
            return "OpenSSL.crypto.Error"

    def tiny_checker_data(self):
        file_object=open(self.filename,"rb")
        data=file_object.read()
        tiny_checker=binary_checker.checker(data)
        
        a = binary_checker.checker(data)
        version=a.run()
        file_object.close()
        return version

    def getEntropy(self):
        return Str_Ent.getEntropy(self.filename)
      
    def getstr(self):
        return Str_Ent.exstrings(self.filename)

    def characteristics(self):
        result_list=combinations(target,characteristics_data,int(self.pe.NT_HEADERS.FILE_HEADER.Characteristics))
        return result_list
             
    def imagebased(self):
        return hex(self.pe.OPTIONAL_HEADER.ImageBase)
    
    def subsystem(self):
        subsystem_dict={
            'IMAGE_SUBSYSTEM_UNKNOWN':0, 
            'IMAGE_SUBSYSTEM_NATIVE':1,
            'IMAGE_SUBSYSTEM_WINDOWS_GUI':2,
            'IMAGE_SUBSYSTEM_WINDOWS_CUI':3,
            'IMAGE_SUBSYSTEM_OS2_CUI':5,
            'IMAGE_SUBSYSTEM_POSIX_CUI':7,
            'IMAGE_SUBSYSTEM_NATIVE_WINDOWS':8,
            'IMAGE_SUBSYSTEM_WINDOWS_CE_GUI':9,
            'IMAGE_SUBSYSTEM_EFI_APPLICATION':10,
            'IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER':11,
            'IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER':12,
            'IMAGE_SUBSYSTEM_EFI_ROM':13,
            'IMAGE_SUBSYSTEM_XBOX':14,
            'IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION':16
        }
        subsystem_num=self.pe.OPTIONAL_HEADER.Subsystem
        for subsystem_dict_key,subsystem_dict_values in subsystem_dict.items():
            if subsystem_num==subsystem_dict_values:
                
                return {subsystem_dict_key:hex(subsystem_num)}

    def filetypes(self):
        kind = filetype.guess(self.filename)
        if kind is None:
            return None
        return {kind.extension:kind.mime}
    
    def CheckSumd(self):
        return hex(self.pe.OPTIONAL_HEADER.CheckSum)
    
    def FileAlignment(self):
        return self.pe.OPTIONAL_HEADER.FileAlignment
    
    def entrypoint(self):
        return hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    
    def SectionAlignment(self):
        return hex(self.pe.OPTIONAL_HEADER.SectionAlignment)
    
    def Sectioninfo(self):
        sections_dict={}
        for sections in self.pe.sections:
            try:
                sections_dict[sections.Name.decode().replace("\x00","")]=[sections.get_hash_sha256(),hex(sections.PointerToRawData)]
            except:
                sname=sections.Name.decode('latin-1').encode('utf-8').decode('utf-8').replace('\x00','')
                sname=list(sname)
                if sname[0]!='.':
                    del(sname[0])
                sections_dict[''.join(sname)]=[sections.get_hash_sha256(),hex(sections.PointerToRawData)]


        return sections_dict

    def section_data(self):
        sections_dict = {}
        section_list=['text']
        for sections in self.pe.sections:
            if sections.Name.decode().replace("\x00","").replace('.','') in section_list:
                data=''.join([chr(data) for data in sections.get_data() if 39<ord(chr(data))<127])

                sections_dict[sections.Name.decode().replace("\x00","")]=data
        return sections_dict

    def ImportDll(self):
        ImportDlldict={}
        try:
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                importlists=[]
                for imp in entry.imports:
                    try:
                        importlists.append(imp.name.decode())
                    except:
                        continue
                ImportDlldict[entry.dll.decode()]=importlists
        except:
            return None
        return ImportDlldict


    
    
    def run(self,pe_info_json):
        pe_info_json['pe_success']=1
        pe_info_json['pe_groups']=None
        
        pe_info_json['pe_random']=os.path.splitext(os.path.basename(self.filename))[0]
        pe_info_json['pe_md5']=self.md5_data()
        pe_info_json['pe_sha256']=self.sha256_data()
        pe_info_json['pe_pdb']=self.pdb_data()
        pe_info_json['pe_richheader']=RichHeader_data(self.filename)
        pe_info_json['pe_section_entropy']=self.getEntropy()
        pe_info_json['pe_strings']=self.getstr()
        pe_info_json['pe_EntryPoint']=self.entrypoint()
        pe_info_json['pe_FileAlignment']=self.FileAlignment()
        pe_info_json['pe_PeFileType']=self.filetypes()
        pe_info_json['pe_Characteristics']=self.characteristics()
        pe_info_json['pe_ImageBase']=self.imagebased()
        pe_info_json['pe_Subsystem']=self.subsystem()
        pe_info_json['pe_section_data']=self.section_data()
        pe_info_json['pe_StoredChecksum']=self.CheckSumd()
        pe_info_json['pe_imphash']=self.imphash_data()
        pe_info_json['pe_codesign']=self.codesign_data()
        pe_info_json['pe_packed']=self.tiny_checker_data()
        pe_info_json['pe_SectionAlignment']=self.SectionAlignment()
        pe_info_json['pe_sectioninfo']=self.Sectioninfo()
        pe_info_json['pe_importdll']=self.ImportDll()
        
        self.pe.close()
        return pe_info_json

    
    
    
    
    
    
    
    

####################################################################################
def pe_check(file_path):
    try:
        pe = pefile.PE(file_path, fast_load=True)
        # AddressOfEntryPoint if guaranteed to be the first byte executed.
    except:
        return False
    signature_hex= hex(pe.NT_HEADERS.Signature)
    pe.close()
    if signature_hex=='0x4550':
        return True
    else:
        return False

####################################################################################
import copy
characteristics_dict={
    'IMAGE_FILE_RELOCS_STRIPPED':0x0001,  #// Relocation info stripped from file.
    'IMAGE_FILE_EXECUTABLE_IMAGE':0x0002,  #// File is executable  (i.e. no unresolved externel references).
    'IMAGE_FILE_LINE_NUMS_STRIPPED':0x0004,  #// Line nunbers stripped from file.
    'IMAGE_FILE_LOCAL_SYMS_STRIPPED':0x0008,  #// Local symbols stripped from file.
    'IMAGE_FILE_AGGRESIVE_WS_TRIM':0x0010,  #// Agressively trim working set
    'IMAGE_FILE_LARGE_ADDRESS_AWARE':0x0020,  #// App can handle >2gb addresses
    'IMAGE_FILE_BYTES_REVERSED_LO':0x0080,  #// Bytes of machine word are reversed.
    'IMAGE_FILE_32BIT_MACHINE':0x0100,  #// 32 bit word machine.
    'IMAGE_FILE_DEBUG_STRIPPED':0x0200,  #// Debugging info stripped from file in .DBG file
    'IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP':0x0400,  #// If Image is on removable media, copy and run from the swap file.
    'IMAGE_FILE_NET_RUN_FROM_SWAP':0x0800,  #// If Image is on Net, copy and run from the swap file.
    'IMAGE_FILE_SYSTEM':0x1000,  #// System File.
    'IMAGE_FILE_DLL':0x2000,  #// File is a DLL.
    'IMAGE_FILE_UP_SYSTEM_ONLY':0x4000,  #// File should only be run on a UP machine
    'IMAGE_FILE_BYTES_REVERSED_HI':0x8000  #// Bytes of machine word are reversed.
}
target=[]
characteristics_data=list(characteristics_dict.values())
result_list=[]
def combinations(target,data,constant_value):
    for i in range(len(data)):
        new_target = copy.copy(target)
        new_data = copy.copy(data)
        new_target.append(data[i])
        new_data = data[i+1:]
        new_data_sum=sum(new_target)
        if new_data_sum==constant_value:
            for characteristics_key, characteristics_values in characteristics_dict.items():
                for target_object in new_target:
                    if characteristics_values == target_object:
                        result_list.append(characteristics_key)
        combinations(new_target,new_data,constant_value)
    return result_list

 ####################################################################################
def result_all(filename):
    pe_info_json={
        ############Binary Information############
        'pe_sha256':None,
        'pe_md5':None,
        'pe_packed':None,
        ############PE Information############
        'pe_Subsystem':None,
        'pe_ImageBase':None,
        'pe_Characteristics':None,
        'pe_PeFileType':None,
        'pe_StoredChecksum':None,
        'pe_FileAlignment':None,
        'pe_EntryPoint':None,
        'pe_SectionAlignment':None,
        ############PE Section Information############
        'pe_sectioninfo':None,

        ############PE Import Information############
        'pe_importdll':None,


        ############About Similarity###########
        'pe_success':None,

        'pe_strings':None,
        'pe_pdb':None,
        'pe_imphash':None,
        'pe_codesign':None,
        'pe_section_entropy':None,
        'pe_richheader':None,

        ##########etc############################
        'pe_random':None,
        'pe_groups':None,
        'pe_tags': None,
        'pe_section_data':None
    }
    
    pe_check_result=pe_check(filename)
    if pe_check_result==False:
        pe_info_json["pe_success"]==0
        return pe_info_json
    try:
        pe_anal = PE_analyzer(filename)
        result_pe_info_json = pe_anal.run(pe_info_json)
    except:
        return pe_info_json

    return result_pe_info_json

def closed():
    print(os.getpid())
    os.kill(os.getpid(),signal.SIGTERM)
    
if __name__ == '__main__':
    filename = 'D:\\Allinone\\BOB\\Python\\Tensflow\\samples\\mal_samples\\kimsuky\\[OLD_KIMSUKY]ffad0446f46d985660ce1337c9d5eaa2'
    result_pe_info_json=result_all(filename)
    #os.remove(filename)
    print(json.dumps(result_pe_info_json, indent=4))
