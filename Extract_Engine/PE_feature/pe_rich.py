import struct
'''
<Rich header format>
ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
|                Dans Anchor                |                  Null Padding               |
|                Null Padding               |                  Null Padding               |
ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
|           mCV        |        ProdID      |                  Null Padding               |
|           mCV        |        ProdID      |                  Null Padding               |
ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
|                Rich identifier            |                     count                   |
|                   Padding                 |                     Padding                 |
ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
|         2byte        |        2byte       |          2byte        |        2byte        |  

'''
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

#리치헤더가 없을 시 예외처리 클래스
class RichHeaderNotFoundException(Exception):
    def __init__(self):
        Exception.__init__(self, "Rich does not appear to exist")

'''
    PE파일에서 rich 헤더 부분만 추출하기 위한 함수
    1. open file
    2. find start_pe_header_address
    3. extract data from 0x80 ~ start_pe_header_address
'''
def get_rich_section(file_name):

    '''
        1. 0x3c ~ 0x40 : start pe_header address
        2. 0x80 ~ start pe_header address : rich_header section scope
    '''

    fp=open(file_name,'rb')

    data=fp.read()

    if data == '': raise RichHeaderNotFoundException()     # exception no rich
    end = struct.unpack('<I', data[0x3c:0x40])[0]             # find start address of pe_header
    data = data[0x80:end]                                   # read 0x00 ~ end(pe header)
    fp.close()

    return data


class ParseRichHeader:
    '''
        PE파일을 읽은 뒤 리치헤더와 관련된 정보를 추출하고
        추출된 정보를 가지고 추후에 유사도 평가에 부가적인 옵션으로 적용될 클래스
        리치헤더를 분석할 PE 파일 경로 및 파일 명을 처음으로 받는다
    '''
    def __init__(self, file_name):
        self.file_name=file_name
        self.parse(file_name)
        # processing pe file for extract rich header
        # parse function return riche_header data section from file_name

    def parse(self, file_name):
        data = get_rich_section(file_name)
        rich_identifi_addr = data.find(b'Rich')

        if rich_identifi_addr == -1 : raise RichHeaderNotFoundException()       # if rich_header no exit

        rich_offset = rich_identifi_addr + 4
        checksum_text = data[rich_offset : rich_offset+4]
        self.xorkey = struct.unpack('<I', checksum_text)[0]
        self.data= data[:rich_identifi_addr]

        self.info_list=dict()                                                   # store compID and count

        for i in range(16, rich_identifi_addr, 8):
            compID = struct.unpack('<L', self.data[i:i+4])[0] ^ self.xorkey     # extract compID(mVC,prodID)
            count = struct.unpack('<L', self.data[i+4:i+8])[0] ^ self.xorkey    # extract count
            self.info_list[compID]=count

    def extract_prodid(self):                                                   # prodid
        set1 = []
        for i in self.info_list:
            set1.append(i.prodid)
        return set1

    def extract_clear_data(self):                                               # clear_data is (compid,count)
        set1 = []
        for i in self.info_list:
            set1.append(hex(i.compid))
            set1.append(hex(i.count))
        return (set1)

'''
class Info:
    def __init__(self, compID, count):
        self.compid = compID
        self.prodid = compID >> 16
        self.build = compID & 0xffff
        self.count = count
'''

'''
if __name__ == "__main__":
    PATH="D:\\JungJaeho\\STUDY\\self\\BOB\\BoB_Project\\Team_Breakers\\Training\\Study\\sample\\mid_GandCrab_exe\\2cb5cfdc436638575323eac73ed36acd84b4694c144a754772c67167b99d574c"
    rich= ParseRichHeader(PATH)
    xor_key=rich.xorkey

    print(f'XorKey : {xor_key}')
    print("ProID    name              count")
    for key in rich.info_list.keys():
        count=rich.info_list[key]
        prodid=(key>>16)
        prodid_name = PRODID_MAP[prodid] if prodid in PRODID_MAP else "<unknown>"
        print('%6d   %-15s %5d' % (prodid, prodid_name, count))
'''