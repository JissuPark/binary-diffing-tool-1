import pefile
import json

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

UNKNOWN_COMP = {
    # MSVS2019 v16.0.0
    '0x1046b74': '[ C ] VS2019 v16.0.0 build 27508',
    '0x1036b74': '[ASM] VS2019 v16.0.0 build 27508',
    '0x1056b74': '[C++] VS2019 v16.0.0 build 27508',
    '0xff6b74': '[RES] VS2019 v16.0.0 build 27508',
    '0x1026b74': '[LNK] VS2019 v16.0.0 build 27508',
    '0x1006b74': '[EXP] VS2019 v16.0.0 build 27508',
    '0x1016b74': '[IMP] VS2019 v16.0.0 build 27508',

    # RTM version number: 18.0.21005.1
    # Update 2 version number: 18.00.30501
    # Update 3 version number: 18.00.30723
    # Update 4 version number: 18.00.31101

    # MSVS2017 v15.5.4
    '0x10464ea': '[ C ] VS2017 v15.5.4 build 25834',
    '0x10364ea': '[ASM] VS2017 v15.5.4 build 25834',
    '0x10564ea': '[C++] VS2017 v15.5.4 build 25834',
    '0xff64ea': '[RES] VS2017 v15.5.4 build 25834',
    '0x10264ea': '[LNK] VS2017 v15.5.4 build 25834',
    '0x10064ea': '[EXP] VS2017 v15.5.4 build 25834',
    '0x10164ea': '[IMP] VS2017 v15.5.4 build 25834',

    # MSVS Community 2015 UPD3.1 (cl version 19.00.24215.1) - some IDs are interpolated
    # [ASM] is the same as in UPD3 build 24213
    '0x1045e97': '[ C ] VS2015 UPD3.1 build 24215',
    '0x1055e97': '[C++] VS2015 UPD3.1 build 24215',
    '0x1025e97': '[LNK] VS2015 UPD3.1 build 24215',
    '0x1005e97': '[EXP] VS2015 UPD3.1 build 24215',
    '0x1015e97': '[IMP] VS2015 UPD3.1 build 24215',

    # MSVS Community 2015 UPD3 (cl version 19.00.24213.1)
    '0x1045e95': '[ C ] VS2015 UPD3 build 24213',
    '0x1035e92': '[ASM] VS2015 UPD3 build 24210',
    '0x1055e95': '[C++] VS2015 UPD3 build 24213',
    '0xff5e92': '[RES] VS2015 UPD3 build 24210',
    '0x1025e95': '[LNK] VS2015 UPD3 build 24213',
    '0x1005e95': '[EXP] VS2015 UPD3 build 24213',
    '0x1015e95': '[IMP] VS2015 UPD3 build 24213',

    # MSVS Community 2015 UPD2 (14.0.25123.0?)
    '0x1045d6e': '[ C ] VS2015 UPD2 build 23918',
    '0x1035d6e': '[ASM] VS2015 UPD2 build 23918',
    '0x1055d6e': '[C++] VS2015 UPD2 build 23918',
    '0xff5d6e': '[RES] VS2015 UPD2 build 23918',
    '0x1025d6e': '[LNK] VS2015 UPD2 build 23918',
    '0x1005d6e': '[EXP] VS2015 UPD2 build 23918',
    '0x1015d6e': '[IMP] VS2015 UPD2 build 23918',

    # MSVS Community 2015 14.0.24728.2 (UPD 1) 14.0.24720.0 D14REL
    '0x1045bd2': '[ C ] VS2015 UPD1 build 23506',
    '0x1035bd2': '[ASM] VS2015 UPD1 build 23506',
    '0x1055bd2': '[C++] VS2015 UPD1 build 23506',
    '0xff5bd2': '[RES] VS2015 UPD1 build 23506',
    '0x1025bd2': '[LNK] VS2015 UPD1 build 23506',
    '0x1005bd2': '[EXP] VS2015 UPD1 build 23506',
    '0x1015bd2': '[IMP] VS2015 UPD1 build 23506',

    # MSVS Community 2015
    '0x10459f2': '[ C ] VS2015 build 23026',
    '0x10359f2': '[ASM] VS2015 build 23026',
    '0x10559f2': '[C++] VS2015 build 23026',
    '0xff59f2': '[RES] VS2015 build 23026',
    '0x10259f2': '[LNK] VS2015 build 23026',
    '0x10059f2': '[EXP] VS2015 build 23026',
    '0x10159f2': '[IMP] VS2015 build 23026',

    # MSVS2013 12.0.40629.00 Update 5
    '0xe09eb5': '[ C ] VS2013 UPD5 build 40629',
    '0xe19eb5': '[C++] VS2013 UPD5 build 40629',
    # cvtres not updated since RTM version
    '0xde9eb5': '[LNK] VS2013 UPD5 build 40629',
    '0xdc9eb5': '[EXP] VS2013 UPD5 build 40629',
    '0xdd9eb5': '[IMP] VS2013 UPD5 build 40629',
    '0xdf9eb5': '[ASM] VS2013 UPD5 build 40629',

    # MSVS2013 12.0.31101.00 Update 4 - not attested in real world, @comp.id is
    # calculated.
    '0xe0797d': '[ C ] VS2013 UPD4 build 31101',
    '0xe1797d': '[C++] VS2013 UPD4 build 31101',
    # cvtres not updated since RTM version
    '0xde797d': '[LNK] VS2013 UPD4 build 31101',
    '0xdc797d': '[EXP] VS2013 UPD4 build 31101',
    '0xdd797d': '[IMP] VS2013 UPD4 build 31101',
    '0xdf797d': '[ASM] VS2013 UPD4 build 31101',

    # MSVS2013 12.0.30723.00 Update 3 - not attested in real world, @comp.id is
    # calculated.
    '0xe07803': '[ C ] VS2013 UPD3 build 30723',
    '0xe17803': '[C++] VS2013 UPD3 build 30723',
    # cvtres not updated since RTM version
    '0xde7803': '[LNK] VS2013 UPD3 build 30723',
    '0xdc7803': '[EXP] VS2013 UPD3 build 30723',
    '0xdd7803': '[IMP] VS2013 UPD3 build 30723',
    '0xdf7803': '[ASM] VS2013 UPD3 build 30723',

    # MSVS2013 12.0.30501.00 Update 2 - not attested in real world, @comp.id is
    # calculated.
    '0xe07725': '[ C ] VS2013 UPD2 build 30501',
    '0xe17725': '[C++] VS2013 UPD2 build 30501',
    # cvtres not updated since RTM version
    '0xde7725': '[LNK] VS2013 UPD2 build 30501',
    '0xdc7725': '[EXP] VS2013 UPD2 build 30501',
    '0xdd7725': '[IMP] VS2013 UPD2 build 30501',
    '0xdf7725': '[ASM] VS2013 UPD2 build 30501',

    # MSVS2013 RTM
    # Looks like it doesn't always dump linker's comp.id
    '0xe0520d': '[ C ] VS2013 build 21005',
    '0xe1520d': '[C++] VS2013 build 21005',
    '0xdb520d': '[RES] VS2013 build 21005',
    '0xde520d': '[LNK] VS2013 build 21005',
    '0xdc520d': '[EXP] VS2013 build 21005',
    '0xdd520d': '[IMP] VS2013 build 21005',
    '0xdf520d': '[ASM] VS2013 build 21005',

    # MSVS2012 Premium Update 4 (11.0.61030.00 Update 4)
    '0xceee66': '[ C ] VS2012 UPD4 build 61030',
    '0xcfee66': '[C++] VS2012 UPD4 build 61030',
    '0xcdee66': '[ASM] VS2012 UPD4 build 61030',
    '0xc9ee66': '[RES] VS2012 UPD4 build 61030',
    '0xccee66': '[LNK] VS2012 UPD4 build 61030',
    '0xcaee66': '[EXP] VS2012 UPD4 build 61030',
    '0xcbee66': '[IMP] VS2012 UPD4 build 61030',

    # MSVS2012 Update 3 (17.00.60610.1 Update 3) - not attested in real world,
    # @comp.id is calculated.
    '0xceecc2': '[ C ] VS2012 UPD3 build 60610',
    '0xcfecc2': '[C++] VS2012 UPD3 build 60610',
    '0xcdecc2': '[ASM] VS2012 UPD3 build 60610',
    '0xc9ecc2': '[RES] VS2012 UPD3 build 60610',
    '0xccecc2': '[LNK] VS2012 UPD3 build 60610',
    '0xcaecc2': '[EXP] VS2012 UPD3 build 60610',
    '0xcbecc2': '[IMP] VS2012 UPD3 build 60610',

    # MSVS2012 Update 2 (17.00.60315.1 Update 2) - not attested in real world,
    # @comp.id is calculated.
    '0xceeb9b': '[ C ] VS2012 UPD2 build 60315',
    '0xcfeb9b': '[C++] VS2012 UPD2 build 60315',
    '0xcdeb9b': '[ASM] VS2012 UPD2 build 60315',
    '0xc9eb9b': '[RES] VS2012 UPD2 build 60315',
    '0xcceb9b': '[LNK] VS2012 UPD2 build 60315',
    '0xcaeb9b': '[EXP] VS2012 UPD2 build 60315',
    '0xcbeb9b': '[IMP] VS2012 UPD2 build 60315',

    # MSVS2012 Update 1 (17.00.51106.1 Update 1) - not attested in real world,
    # @comp.id is calculated.
    '0xcec7a2': '[ C ] VS2012 UPD1 build 51106',
    '0xcfc7a2': '[C++] VS2012 UPD1 build 51106',
    '0xcdc7a2': '[ASM] VS2012 UPD1 build 51106',
    '0xc9c7a2': '[RES] VS2012 UPD1 build 51106',
    '0xccc7a2': '[LNK] VS2012 UPD1 build 51106',
    '0xcac7a2': '[EXP] VS2012 UPD1 build 51106',
    '0xcbc7a2': '[IMP] VS2012 UPD1 build 51106',

    # MSVS2012 Premium (11.0.50727.1 RTMREL)
    '0xcec627': '[ C ] VS2012 build 50727',
    '0xcfc627': '[C++] VS2012 build 50727',
    '0xc9c627': '[RES] VS2012 build 50727',
    '0xcdc627': '[ASM] VS2012 build 50727',
    '0xcac627': '[EXP] VS2012 build 50727',
    '0xcbc627': '[IMP] VS2012 build 50727',
    '0xccc627': '[LNK] VS2012 build 50727',

    # MSVS2010 SP1 kb 983509 (10.0.40219.1 SP1Rel)
    '0xaa9d1b': '[ C ] VS2010 SP1 build 40219',
    '0xab9d1b': '[C++] VS2010 SP1 build 40219',
    '0x9d9d1b': '[LNK] VS2010 SP1 build 40219',
    '0x9a9d1b': '[RES] VS2010 SP1 build 40219',
    '0x9b9d1b': '[EXP] VS2010 SP1 build 40219',
    '0x9c9d1b': '[IMP] VS2010 SP1 build 40219',
    '0x9e9d1b': '[ASM] VS2010 SP1 build 40219',

    # MSVS2010 (10.0.30319.1 RTMRel)
    '0xaa766f': '[ C ] VS2010 build 30319',
    '0xab766f': '[C++] VS2010 build 30319',
    '0x9d766f': '[LNK] VS2010 build 30319',
    '0x9a766f': '[RES] VS2010 build 30319',
    '0x9b766f': '[EXP] VS2010 build 30319',
    '0x9c766f': '[IMP] VS2010 build 30319',
    '0x9e766f': '[ASM] VS2010 build 30319',

    # MSVS2008 SP1 (9.0.30729.1 SP)
    '0x837809': '[ C ] VS2008 SP1 build 30729',
    '0x847809': '[C++] VS2008 SP1 build 30729',
    # cvtres is the same as in VS2008
    '0x957809': '[ASM] VS2008 SP1 build 30729',
    '0x927809': '[EXP] VS2008 SP1 build 30729',
    '0x937809': '[IMP] VS2008 SP1 build 30729',
    '0x917809': '[LNK] VS2008 SP1 build 30729',

    # MSVS2008 (9.0.21022.8 RTM)
    '0x83521e': '[ C ] VS2008 build 21022',
    '0x84521e': '[C++] VS2008 build 21022',
    '0x91521e': '[LNK] VS2008 build 21022',
    '0x94521e': '[RES] VS2008 build 21022',
    '0x92521e': '[EXP] VS2008 build 21022',
    '0x93521e': '[IMP] VS2008 build 21022',
    '0x95521e': '[ASM] VS2008 build 21022',

    # MSVS2005 (RTM.50727-4200) cl version: 14.00.50727.42
    # MSVS2005-SP1 dumps the same comp.id's.
    # It is strange, but there exists VS2012 with the same build number:
    # 11 Build 50727.1
    '0x6dc627': '[ C ] VS2005 build 50727',
    '0x6ec627': '[C++] VS2005 build 50727',
    '0x78c627': '[LNK] VS2005 build 50727',
    '0x7cc627': '[RES] VS2005 build 50727',
    '0x7ac627': '[EXP] VS2005 build 50727',
    '0x7bc627': '[IMP] VS2005 build 50727',
    '0x7dc627': '[ASM] VS2005 build 50727',

    # MSVS2003 (.NET) SP1 (kb918007)
    '0x5f178e': '[ C ] VS2003 (.NET) SP1 build 6030',
    '0x60178e': '[C++] VS2003 (.NET) SP1 build 6030',
    '0x5a178e': '[LNK] VS2003 (.NET) SP1 build 6030',
    '0xf178e': '[ASM] VS2003 (.NET) SP1 build 6030',
    # cvtres is the same version as without SP1
    '0x5c178e': '[EXP] VS2003 (.NET) SP1 build 6030',
    '0x5d178e': '[IMP] VS2003 (.NET) SP1 build 6030',

    # MSVS2003 (.NET) 7.0.1.3088
    '0x5f0c05': '[ C ] VS2003 (.NET) build 3077',
    '0x600c05': '[C++] VS2003 (.NET) build 3077',
    '0xf0c05': '[ASM] VS2003 (.NET) build 3077',
    '0x5e0bec': '[RES] VS2003 (.NET) build 3052',
    '0x5c0c05': '[EXP] VS2003 (.NET) build 3077',
    '0x5d0c05': '[IMP] VS2003 (.NET) build 3077',
    '0x5a0c05': '[LNK] VS2003 (.NET) build 3077',

    # MSVS2002 (.NET) 7.0.9466
    '0x1c24fa': '[ C ] VS2002 (.NET) build 9466',
    '0x1d24fa': '[C++] VS2002 (.NET) build 9466',
    '0x4024fa': '[ASM] VS2002 (.NET) build 9466',
    '0x3d24fa': '[LNK] VS2002 (.NET) build 9466',
    '0x4524fa': '[RES] VS2002 (.NET) build 9466',
    '0x3f24fa': '[EXP] VS2002 (.NET) build 9466',
    '0x1924fa': '[IMP] VS2002 (.NET) build 9466',

    # MSVS98 6.0 SP6 (Enterprise edition)
    # Looks like linker may mix compids for C and C++ objects (why?)
    '0xa2636': '[ C ] VS98 (6.0) SP6 build 8804',
    '0xb2636': '[C++] VS98 (6.0) SP6 build 8804',

    # MSVC++ 6.0 SP5 (Enterprise edition)
    '0x152306': '[ C ] VC++ 6.0 SP5 build 8804',
    '0x162306': '[C++] VC++ 6.0 SP5 build 8804',
    '0x420ff': '[LNK] VC++ 6.0 SP5 imp/exp build 8447',
    '0x606c7': '[RES] VS98 (6.0) SP6 cvtres build 1736',

    # MSVS6.0 (no servicepacks)
    '0xa1fe8': '[ C ] VS98 (6.0) build 8168',
    '0xb1fe8': '[C++] VS98 (6.0) build 8168',
    '0x606b8': '[RES] VS98 (6.0) cvtres build 1720',
    '0x41fe8': '[LNK] VS98 (6.0) imp/exp build 8168'
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

class ParseRichHeader:
    '''
        PE파일을 읽은 뒤 리치헤더와 관련된 정보를 추출하고
        추출된 정보를 가지고 추후에 유사도 평가에 부가적인 옵션으로 적용될 클래스
        리치헤더를 분석할 PE 파일 경로 및 파일 명을 처음으로 받는다
    '''
    def __init__(self, file_name):
        self.file_name=file_name

    def parse(self, file_name):
        pe = pefile.PE(file_name)

        try:
            rich = pe.parse_rich_header()
            prod = dict()
            prod_list = list()

            for key in rich:
                if key == 'checksum':
                    xorkey = rich[key]
                    prod['xor key'] = xorkey
                if key == 'values':
                    for i in range(len(rich[key])):
                        if i % 2 == 0:
                            compid = (rich[key][i] >> 16)
                            prod_list.append(compid)
                            if compid in PRODID_MAP:
                                prodid_name = PRODID_MAP[compid]
                            else:
                                #print(f"{hex(rich[key][i])} :: {compid} is not in PRODID_MAP")
                                if hex(rich[key][i]) in UNKNOWN_COMP:
                                    prodid_name = UNKNOWN_COMP[hex(rich[key][i])]
                                else:
                                    prodid_name = rich[key][i]
                        else:
                            count = rich[key][i]
                            prod[prodid_name] = count
            return xorkey, prod_list, prod
        except:
            return "-", [], {}