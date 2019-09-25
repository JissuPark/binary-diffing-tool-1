import pefile, os
import json
from hashlib import sha256

COUNTRY_MAP = {
    0: "Unicode",
    1025: "Arabic - Saudi Arabia",
    1026: "Bulgarian",
    1027: "Catalan",
    1028: "Chinese - Taiwan",
    1029: "Czech",
    1030: "Danish",
    1031: "German - Germany",
    1032: "Greek",
    1033: "English - United States",
    1034: "Spanish - Spain (Traditional)",
    1035: "Finnish",
    1036: "French - France",
    1037: "Hebrew",
    1038: "Hungarian",
    1039: "Icelandic",
    1040: "Italian - Italy",
    1041: "Japanese",
    1042: "Korean",
    1043: "Dutch - Netherlands",
    1044: "Norwegian - Bokml",
    1045: "Polish",
    1046: "Portuguese - Brazil",
    1047: "Raeto-Romance",
    1048: "Romanian - Romania",
    1049: "Russian",
    1050: "Croatian",
    1051: "Slovak",
    1052: "Albanian",
    1053: "Swedish - Sweden",
    1054: "Thai",
    1055: "Turkish",
    1056: "Urdu",
    1057: "Indonesian",
    1058: "Ukrainian",
    1059: "Belarusian",
    1060: "Slovenian",
    1061: "Estonian",
    1062: "Latvian",
    1063: "Lithuanian",
    1064: "Tajik",
    1065: "Farsi - Persian",
    1066: "Vietnamese",
    1067: "Armenian",
    1068: "Azeri - Latin",
    1069: "Basque",
    1070: "Sorbian",
    1071: "FYRO Macedonia",
    1072: "Sesotho (Sutu)",
    1073: "Tsonga",
    1074: "Setsuana",
    1075: "Venda",
    1076: "Xhosa",
    1077: "Zulu",
    1078: "Afrikaans",
    1079: "Georgian",
    1080: "Faroese",
    1081: "Hindi",
    1082: "Maltese",
    1083: "Sami Lappish",
    1084: "Gaelic - Scotland",
    1085: "Yiddish",
    1086: "Malay - Malaysia",
    1087: "Kazakh",
    1088: "Kyrgyz - Cyrillic",
    1089: "Swahili",
    1090: "Turkmen",
    1091: "Uzbek - Latin",
    1092: "Tatar",
    1093: "Bengali - India",
    1094: "Punjabi",
    1095: "Gujarati",
    1096: "Oriya",
    1097: "Tamil",
    1098: "Telugu",
    1099: "Kannada",
    1100: "Malayalam",
    1101: "Assamese",
    1102: "Marathi",
    1103: "Sanskrit",
    1104: "Mongolian",
    1105: "Tibetan",
    1106: "Welsh",
    1107: "Khmer",
    1108: "Lao",
    1109: "Burmese",
    1110: "Galician",
    1111: "Konkani",
    1112: "Manipuri",
    1113: "Sindhi",
    1114: "Syriac",
    1115: "Sinhala",
    1118: "Amharic",
    1120: "Kashmiri",
    1121: "Nepali",
    1122: "Frisian - Netherlands",
    1124: "Filipino",
    1126: "Edo",
    1136: "Igbo - Nigeria",
    1140: "Guarani - Paraguay",
    1142: "Latin",
    1143: "Somali",
    1153: "Maori",
    1279: "HID (Human Interface Device)",
    2049: "Arabic - Iraq",
    2052: "Chinese - China",
    2055: "German - Switzerland",
    2057: "English - Great Britain",
    2058: "Spanish - Mexico",
    2060: "French - Belgium",
    2064: "Italian - Switzerland",
    2067: "Dutch - Belgium",
    2068: "Norwegian - Nynorsk",
    2070: "Portuguese - Portugal",
    2072: "Romanian - Moldova",
    2073: "Russian - Moldova",
    2074: "Serbian - Latin",
    2077: "Swedish - Finland",
    2092: "Azeri - Cyrillic",
    2108: "Gaelic - Ireland",
    2110: "Malay - Brunei",
    2115: "Uzbek - Cyrillic",
    2117: "Bengali - Bangladesh",
    2128: "Mongolian",
    3073: "Arabic - Egypt",
    3076: "Chinese - Hong Kong SAR",
    3079: "German - Austria",
    3081: "English - Australia",
    3084: "French - Canada",
    3098: "Serbian - Cyrillic",
    4097: "Arabic - Libya",
    4100: "Chinese - Singapore",
    4103: "German - Luxembourg",
    4105: "English - Canada",
    4106: "Spanish - Guatemala",
    4108: "French - Switzerland",
    5121: "Arabic - Algeria",
    5124: "Chinese - Macau SAR",
    5127: "German - Liechtenstein",
    5129: "English - New Zealand",
    5130: "Spanish - Costa Rica",
    5132: "French - Luxembourg",
    5146: "Bosnian",
    6145: "Arabic - Morocco",
    6153: "English - Ireland",
    6154: "Spanish - Panama",
    6156: "French - Monaco",
    7169: "Arabic - Tunisia",
    7177: "English - Southern Africa",
    7178: "Spanish - Dominican Republic",
    7180: "French - West Indies",
    8193: "Arabic - Oman",
    8201: "English - Jamaica",
    8202: "Spanish - Venezuela",
    9217: "Arabic - Yemen",
    9225: "English - Caribbean",
    9226: "Spanish - Colombia",
    9228: "French - Congo",
    10241: "Arabic - Syria",
    10249: "English - Belize",
    10250: "Spanish - Peru",
    10252: "French - Senegal",
    11265: "Arabic - Jordan",
    11273: "English - Trinidad",
    11274: "Spanish - Argentina",
    11276: "French - Cameroon",
    12289: "Arabic - Lebanon",
    12297: "English - Zimbabwe",
    12298: "Spanish - Ecuador",
    12300: "French - Cote d'Ivoire",
    13313: "Arabic - Kuwait",
    13321: "English - Philippines",
    13322: "Spanish - Chile",
    13324: "French - Mali",
    14337: "Arabic - United Arab Emirates",
    14346: "Spanish - Uruguay",
    14348: "French - Morocco",
    15361: "Arabic - Bahrain",
    15370: "Spanish - Paraguay",
    16385: "Arabic - Qatar",
    16393: "English - India",
    16394: "Spanish - Bolivia",
    17418: "Spanish - El Salvador",
    18442: "Spanish - Honduras",
    19466: "Spanish - Nicaragua",
    20490: "Spanish - Puerto Rico"
}

'''
def make_country_dic():
    #파일을 읽어서 원하는 정보만을 추출해 dictionary 형태로 저장
    with open(r"C:\\Users\qkrwl\PycharmProjects\study\language.txt", 'r') as lgg:
        lines = lgg.readlines()
        res1 = dict()
        for line in lines:
            country_name = line.split("\t")[0]              #국가이름을 추출
            country_id = int(line.split("\t")[3])           #국가코드(id)를 추출
            res1[country_id] = country_name                 #dic의 형태로 저장

    # 국가의 이름순으로 저장되어있으므로 id순으로 재정렬
    res2 = sorted(res1.items())

    #출력을 통해서 dictionary를 만들 수 있도록 한다.
    for item in res2:
        print(f'{item[0]}: "{item[1]}",')
'''

def match_language(id):
    return COUNTRY_MAP[id] if id in COUNTRY_MAP else "<unknown>"


class RsrcParser:
    def __init__(self, filename):
        self.filename = filename
        self.pe = pefile.PE(self.filename)

    def get_resource(self):
        #리소스 정보를 저장할 리스트
        self.resource = []

        #리소스 엔트리를 가지고 있는지 확인
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            print('PE doesn\'t has DIRECTORY_ENTRY_RESOURCE')
            return -1

        #가지고 있는 엔트리만큼 반복
        for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            #엔트리가 디렉토리를 가지는지 확인
            if not hasattr(resource_type, 'directory'):
                print('This entry doesn\'t has directory')
                continue
            #가지고 있으면 출력
            #print(f'Resource Type is {resource_type.id}')# : {resource_type.struct}')

            #디렉토리를 가지므로 디렉토리 목록에 대해 반복
            for resource_id in resource_type.directory.entries:
                #엔트리가 디렉토리를 가지는지 확인
                if not hasattr(resource_id, 'directory'):
                    print(f'{resource_id} dosen\'t have directory')
                    continue
                #가지고 있으면 출력
                #print(f'Resource NameID is {resource_id.id}')# : {resource_id.struct}')

                #디렉토리를 가지므로 목록에 대해 반복
                for resource_lang in resource_id.directory.entries:
                    rsrc_entry = dict()
                    country = match_language(resource_lang.id)
                    #print(f'Resource Language is {resource_lang.id} : {country}')#{resource_lang.struct}')

                    rsrc_entry['Resource Type'] = resource_type.id
                    rsrc_entry['Resource NameID'] = resource_id.id
                    rsrc_entry['Resource Language'] = country

                    #여기서부터 데이터 추출
                    data = self.pe.get_data(resource_lang.data.struct.OffsetToData,
                                           resource_lang.data.struct.Size)

                    #이 시부레 새끼도 ssdeep 조져야함 중요한 건 ssdeep 조져야 하는 애들이 byte type이라 json에 넣을 수 없단거임
                    #rsrc_entry['data'] = data
                    #print(f'data : {data}')
                    size = resource_lang.data.struct.Size
                    rsrc_entry['size'] = size
                    #print(f'size : {size}')
                    '''
                    entropy = get_entropy(data)
                    print(f'entropy : {entropy}')
                    resource.append([data, size])
                    
                    '''
                    self.resource.append(rsrc_entry)

    def extract_sections_privileges(self):
        section_dict = {}
        known_sections = set(
            ['.text', '.data', '.rdata', '.idata', '.edata', '.rsrc', '.bss', '.crt', '.tls', '.rsrc', '.crt', '.reloc',
             '.edata', '.sdata', '.ndata', '.itext', '.code', 'code'])

        Authority_set = set(
            ['IMAGE_SCN_TYPE_REG', 'IMAGE_SCN_TYPE_COPY', 'IMAGE_SCN_CNT_CODE', 'IMAGE_SCN_CNT_INITIALIZED_DATA',
             'IMAGE_SCN_CNT_UNINITIALIZED_DATA', 'IMAGE_SCN_LNK_OTHER', 'IMAGE_SCN_LNK_INFO', 'IMAGE_SCN_LNK_OVER',
             'IMAGE_SCN_LNK_REMOVE', 'IMAGE_SCN_LNK_COMDAT', 'IMAGE_SCN_MEM_PROTECTED', 'IMAGE_SCN_NO_DEFER_SPEC_EXC',
             'IMAGE_SCN_MEM_LOCKED', 'IMAGE_SCN_LNK_NRELOC_OVFL', 'IMAGE_SCN_MEM_DISCARDABLE', 'IMAGE_SCN_MEM_SHARED',
             'IMAGE_SCN_MEM_EXECUTE', 'IMAGE_SCN_MEM_READ', 'IMAGE_SCN_MEM_WRITE']
        )
        for section in self.pe.sections:
            try:
                # change meaningless parts like '\x00' into empty char
                hash_256 = section.get_hash_sha256()
                section_addr = hex(section.PointerToRawData)
            except:
                sname = section.Name.decode('latin-1').encode('utf-8').decode('utf-8').replace('\x00', '')
                sname = list(sname)
                # if name doesn't start with '.' then delete that part
                if sname[0] != '.':
                    del (sname[0])
                # if name start with '.' then return sah256 hash value and section's start address
                hash_256 = section.get_hash_sha256()
                section_addr = hex(section.PointerToRawData)
        for section in self.pe.sections:
            try:
                # 섹션 이름 추출
                section_name = section.Name.decode().split('\x00')[0]
            except:
                continue
            ####################################
            #           권한 확인 시작           #
            ####################################
            if section.IMAGE_SCN_TYPE_REG == True:
                IMAGE_SCN_TYPE_REG = '0'
            else:
                IMAGE_SCN_TYPE_REG = '1'
            if section.IMAGE_SCN_TYPE_COPY == True:
                IMAGE_SCN_TYPE_COPY = '0'
            else:
                IMAGE_SCN_TYPE_COPY = '1'
            if section.IMAGE_SCN_CNT_CODE == True:
                IMAGE_SCN_CNT_CODE = '0'
            else:
                IMAGE_SCN_CNT_CODE = '1'
            if section.IMAGE_SCN_CNT_INITIALIZED_DATA == True:
                IMAGE_SCN_CNT_INITIALIZED_DATA = '0'
            else:
                IMAGE_SCN_CNT_INITIALIZED_DATA = '1'
            if section.IMAGE_SCN_CNT_UNINITIALIZED_DATA == True:
                IMAGE_SCN_CNT_UNINITIALIZED_DATA = '0'
            else:
                IMAGE_SCN_CNT_UNINITIALIZED_DATA = '1'
            if section.IMAGE_SCN_LNK_OTHER == True:
                IMAGE_SCN_LNK_OTHER = '0'
            else:
                IMAGE_SCN_LNK_OTHER = '1'
            if section.IMAGE_SCN_LNK_INFO == True:
                IMAGE_SCN_LNK_INFO = '0'
            else:
                IMAGE_SCN_LNK_INFO = '1'
            if section.IMAGE_SCN_LNK_OVER == True:
                IMAGE_SCN_LNK_OVER = '0'
            else:
                IMAGE_SCN_LNK_OVER = '1'
            if section.IMAGE_SCN_LNK_REMOVE == True:
                IMAGE_SCN_LNK_REMOVE = '0'
            else:
                IMAGE_SCN_LNK_REMOVE = '1'
            if section.IMAGE_SCN_LNK_COMDAT == True:
                IMAGE_SCN_LNK_COMDAT = '0'
            else:
                IMAGE_SCN_LNK_COMDAT = '1'
            if section.IMAGE_SCN_MEM_PROTECTED == True:
                IMAGE_SCN_MEM_PROTECTED = '0'
            else:
                IMAGE_SCN_MEM_PROTECTED = '1'
            if section.IMAGE_SCN_NO_DEFER_SPEC_EXC == True:
                IMAGE_SCN_NO_DEFER_SPEC_EXC = '0'
            else:
                IMAGE_SCN_NO_DEFER_SPEC_EXC = '1'
            if section.IMAGE_SCN_MEM_LOCKED == True:
                IMAGE_SCN_MEM_LOCKED = '0'
            else:
                IMAGE_SCN_MEM_LOCKED = '1'
            if section.IMAGE_SCN_LNK_NRELOC_OVFL == True:
                IMAGE_SCN_LNK_NRELOC_OVFL = '0'
            else:
                IMAGE_SCN_LNK_NRELOC_OVFL = '1'
            if section.IMAGE_SCN_MEM_DISCARDABLE == True:
                IMAGE_SCN_MEM_DISCARDABLE = '0'
            else:
                IMAGE_SCN_MEM_DISCARDABLE = '1'
            if section.IMAGE_SCN_MEM_SHARED == True:
                IMAGE_SCN_MEM_SHARED = '0'
            else:
                IMAGE_SCN_MEM_SHARED = '1'
            if section.IMAGE_SCN_MEM_EXECUTE == True:
                IMAGE_SCN_MEM_EXECUTE = '0'
            else:
                IMAGE_SCN_MEM_EXECUTE = '1'
            if section.IMAGE_SCN_MEM_READ == True:
                IMAGE_SCN_MEM_READ = '0'
            else:
                IMAGE_SCN_MEM_READ = '1'
            if section.IMAGE_SCN_MEM_WRITE == True:
                IMAGE_SCN_MEM_WRITE = '0'
            else:
                IMAGE_SCN_MEM_WRITE = '1'

            ####################################
            #           권한 확인 종료           #
            ####################################
            section_dict[section_name] = [section.get_entropy(),
                                          hash_256,
                                          section_addr,
                                          hex(section.Characteristics)[2:],
                                          IMAGE_SCN_TYPE_REG,
                                          IMAGE_SCN_TYPE_COPY,
                                          IMAGE_SCN_CNT_CODE,
                                          IMAGE_SCN_CNT_INITIALIZED_DATA,
                                          IMAGE_SCN_CNT_UNINITIALIZED_DATA,
                                          IMAGE_SCN_LNK_OTHER,
                                          IMAGE_SCN_LNK_INFO,
                                          IMAGE_SCN_LNK_OVER,
                                          IMAGE_SCN_LNK_REMOVE,
                                          IMAGE_SCN_LNK_COMDAT,
                                          IMAGE_SCN_MEM_PROTECTED,
                                          IMAGE_SCN_NO_DEFER_SPEC_EXC,
                                          IMAGE_SCN_MEM_LOCKED,
                                          IMAGE_SCN_LNK_NRELOC_OVFL,
                                          IMAGE_SCN_MEM_DISCARDABLE,
                                          IMAGE_SCN_MEM_SHARED,
                                          IMAGE_SCN_MEM_EXECUTE,
                                          IMAGE_SCN_MEM_READ,
                                          IMAGE_SCN_MEM_WRITE
                                          ]
        # non_sus_sections = len(set(tmp).intersection(sections))
        # result = [len(tmp) - non_sus_sections, non_sus_sections]
        # return json.dumps(section_dict, indent=4)
        return section_dict

    def extractPKCS7(self):
        pkcs_dict = dict()
        try:
            # 절대 경로를 통해서 받아옴
            totsize = os.path.getsize(self.filename)
            #ape = pefile.PE(self.filename, fast_load=True)

            # 절대 경로를 통해서 받아옴
            self.pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']])
            sigoff = 0
            siglen = 0

            # 구조체 형태로 정보를 저장
            for s in self.pe.__structures__:
                if s.name == 'IMAGE_DIRECTORY_ENTRY_SECURITY':
                    sigoff = s.VirtualAddress
                    siglen = s.Size

            # 인증서가 있는 부분부터 읽어옴
            if sigoff < totsize:
                f = open(self.filename, 'rb')
                f.seek(sigoff)
                thesig = f.read(siglen)
                f.close()

                # 제대로 인증서를 찾으면 반환
                if 'sign' in str(thesig[8:]).lower() or  'root' in str(thesig[8:]).lower() or 'global' in str(thesig[8:]).lower():
                    pkcs_dict['totalsize'] = totsize
                    pkcs_dict['VirtualAddress'] = sigoff
                    pkcs_dict['Size'] = siglen

                    #이 새끼는 ssdeep으로 조져서 hash값 구해야 돼 근데 내 컴이 ssdeep이 안돼 아주 드러워
                    #pkcs_dict['hash'] = sha256(thesig).hexdigest()
                    return pkcs_dict
                else:
                    return pkcs_dict
        except:
            return pkcs_dict


'''
pe = pefile.PE(r'C:\\Users\qkrwl\Downloads\설치파일\BANDIZIP-SETUP-KR.EXE')

print(get_resource(pe))
#print(pe.get_resources_strings())
print(extract_sections_privileges(pe))
print(extractPKCS7(r'C\\Users\\qkrwl\\Downloads\\Notion Setup 1.0.8.exe'))
'''