import pefile, os
import hashlib
import ssdeep
import array
import math
import struct
from pyasn1.codec.ber.decoder import decode
from pyasn1_modules import rfc2315, rfc2459

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

wRevision_kind = {
    256: "WIN_CERT_REVISION_1_0",
    512: "WIN_CERT_REVISION_2_0"
}

wCertificateType_kind = {
    1: "WIN_CERT_TYPE_X509",
    2: "WIN_CERT_TYPE_PKCS_SIGNED_DATA",
    3: "WIN_CERT_TYPE_RESERVED_1",
    4: "WIN_CERT_TYPE_TS_STACK_SIGNED"
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

def find_wRevision(r):
    return wRevision_kind[r] if r in wRevision_kind else "<NONE>"

def find_wCertificateType(c):
    return wCertificateType_kind[c] if c in wCertificateType_kind else "<NONE>"

class RsrcParser:
    def __init__(self, filename):
        self.filename = filename
        self.pe = pefile.PE(self.filename)

    def get_timestamp(self):
        #print(f"TimeDateStamp : {self.pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1]}")
        Time = self.pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1]
        second = self.pe.FILE_HEADER.TimeDateStamp
        if Time == None: Time = os.utime(self.filename)
        return Time, second

    def get_entropy(self,data):
        if len(data) == 0:
            return 0.0

        occurences = array.array('L', [0] * 256)
        for x in data:
            occurences[x if isinstance(x, int) else ord(x)] += 1

        entropy = 0
        for x in occurences:
            if x:
                p_x = float(x) / len(data)
                entropy -= p_x * math.log(p_x, 2)

        return entropy

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
                    #resouce 데이터(해시화) 출력 성공
                    data = data.decode('Latin-1').replace(u"\u0000", u"").replace(u"\u000B", u"")
                    rsrc_entry['sha-256'] = hashlib.sha256(data.encode()).hexdigest()
                    rsrc_entry['ssdeep'] = ssdeep.hash(data)
                    #print(f'data : {data}')
                    size = resource_lang.data.struct.Size
                    rsrc_entry['size'] = size
                    #print(f'size : {size}')

                    #resource 엔트로피 출력 성공
                    entropy = self.get_entropy(data)
                    #print(f'entropy : {entropy}')
                    rsrc_entry['entropy'] = entropy
                    self.resource.append(rsrc_entry)
        return self.resource

    def extract_sections_privileges(self):
        section_dict = {}
        known_sections = set(
            ['.text', '.data', '.rdata', '.idata', '.edata', '.rsrc', '.bss', '.crt', '.tls', '.rsrc', '.crt', '.reloc',
             '.edata', '.sdata', '.ndata', '.itext', '.code', 'code']
        )
        ### 이부분에 있던 코드들 전부 불필요한 부분이라 삭제
        for section in self.pe.sections:
            try:
                # 섹션 이름 추출
                section_name = section.Name.decode().split('\x00')[0]
                entropy = section.get_entropy()
                hash_ssdeep = ssdeep.hash(section.get_data())
                hash_md5 = hashlib.md5(section.get_data()).hexdigest().upper()
                offset = hex(section.PointerToRawData)
                character = hex(section.Characteristics)[2:]
                virtual_address = section.VirtualAddress
                virtual_size = section.Misc_VirtualSize
                raw_size = section.SizeOfRawData
                # data = ""
                # print("")
                # print(f"{section_name}")
                # for i in range(0, 100000):
                #     data += hex(section.get_data()[i]) + " "
                #     if i != 0 and i % 16 == 0:
                #         print("")
                #     print("%02x" % section.get_data()[i] + " ", end="")
                # print('\n')
            except:
                continue
            #권한 확인 부분 삭제
            #각 섹션별 데이터 해시와 섹션 시작 offset주소부분이 중복되어 출력되서 다음과 같이 수정
            section_dict[section_name] = {
                'section_name': section_name,
                'entropy': entropy,
                'virtual_address': virtual_address,
                'virtual_size': virtual_size,
                'raw_size': raw_size,
                'hash_md5': hash_md5,
                'hash_ssdeep': hash_ssdeep,
                'offset': offset,
                'character': character
            }
        # non_sus_sections = len(set(tmp).intersection(sections))
        # result = [len(tmp) - non_sus_sections, non_sus_sections]
        # return json.dumps(section_dict, indent=4)
        return section_dict

    def extractPKCS7(self):
        pe = pefile.PE(self.filename)
        pkcs_dict = dict()
        try:
            # 절대 경로를 통해서 받아옴
            totsize = os.path.getsize(self.filename)
            #ape = pefile.PE(self.filename, fast_load=True)

            # 절대 경로를 통해서 받아옴
            self.pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']])
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
                #print("printing thesig", thesig[8:].decode('Latin-1'))

                # 제대로 인증서를 찾으면 반환
                if 'sign' in str(thesig[8:]).lower() or 'root' in str(thesig[8:]).lower() or 'global' in str(thesig[8:]).lower():
                    pkcs_dict['dwLength'] = struct.unpack('<L', thesig[0:4])[0]
                    pkcs_dict['wRevision'] = find_wRevision(struct.unpack('<h', thesig[4:6])[0])
                    pkcs_dict['wCertificateType'] = find_wCertificateType(struct.unpack('<h', thesig[6:8])[0])
                    pkcs_dict['VirtualAddress'] = hex(sigoff)
                    pkcs_dict['totalsize'] = totsize

                    #이 새끼는 ssdeep으로 조져서 hash값 구해야 돼 근데 내 컴이 ssdeep이 안돼 아주 드러워
                    #인증서 해시화 성공
                    #thesig = ssdeep.hash(thesig)
                    thesig = hashlib.md5(thesig).hexdigest().upper()
                    pkcs_dict['hash'] = thesig
                address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
                derData = pe.write()[address + 8:]

                (contentInfo, rest) = decode(derData, asn1Spec=rfc2315.ContentInfo())

                contentType = contentInfo.getComponentByName('contentType')

                if contentType == rfc2315.signedData:
                    signedData = decode(contentInfo.getComponentByName('content'), asn1Spec=rfc2315.SignedData())

                for sd in signedData:
                    if sd == '':
                        continue
                    try:
                        signerInfos = sd.getComponentByName('signerInfos')
                    except:
                        continue
                    for si in signerInfos:
                        issuerAndSerial = si.getComponentByName('issuerAndSerialNumber')
                        issuer = issuerAndSerial.getComponentByName('issuer').getComponent()
                        for i in issuer:
                            for r in i:
                                at = r.getComponentByName('type')
                                if rfc2459.id_at_countryName == at:
                                    cn = decode(r.getComponentByName('value'), asn1Spec=rfc2459.X520countryName())
                                    pkcs_dict['Country'] = str(cn[0])
                                elif rfc2459.id_at_organizationName == at:
                                    on = decode(r.getComponentByName('value'), asn1Spec=rfc2459.X520OrganizationName())
                                    pkcs_dict['Company name'] = str(on[0].getComponent())
                                elif rfc2459.id_at_organizationalUnitName == at:
                                    ou = decode(r.getComponentByName('value'), asn1Spec=rfc2459.X520OrganizationalUnitName())
                                    pkcs_dict['Company Unit name'] = str(ou[0].getComponent())
                                elif rfc2459.id_at_commonName == at:
                                    cn = decode(r.getComponentByName('value'), asn1Spec=rfc2459.X520CommonName())
                                    pkcs_dict['Issuer name'] = str(cn[0].getComponent())
                                else:
                                    print(at)
        except:
            return pkcs_dict
        return pkcs_dict


'''
pe = pefile.PE(r'C:\\Users\qkrwl\Downloads\설치파일\BANDIZIP-SETUP-KR.EXE')

print(get_resource(pe))
#print(pe.get_resources_strings())
print(extract_sections_privileges(pe))
print(extractPKCS7(r'C\\Users\\qkrwl\\Downloads\\Notion Setup 1.0.8.exe'))
'''