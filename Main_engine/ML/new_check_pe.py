#-*- coding: utf-8 -*-


import filetype
import csv,os,pefile
import math
import numpy as np
import json
import array
import struct
import binascii
import datetime
import re
import pefile
import sys
#import distorm3
from multiprocessing import Process, current_process ,Queue, Pool

from Main_engine.ML import *

class pe_features():

    def __init__(self):
        pass
        # Need PEiD rules compile with yara
        #self.rules = yara.compile(filepath='D:\\Allinone\\BOB\\Python\\Tensflow\\ClaMP-master\\scripts\\peid.yara')


    ##########sub funtion#################################
    ####################################################
    ##################Section Info Extract###################
    def file_creation_year(self, seconds):
        tmp = 1970 + ((int(seconds) / 86400) / 365)
        return int(tmp in range(1980, 2016))

    def FILE_HEADER_Char_boolean_set(self, pe):
        tmp = [pe.FILE_HEADER.IMAGE_FILE_RELOCS_STRIPPED, \
               pe.FILE_HEADER.IMAGE_FILE_EXECUTABLE_IMAGE, \
               pe.FILE_HEADER.IMAGE_FILE_LINE_NUMS_STRIPPED, \
               pe.FILE_HEADER.IMAGE_FILE_LOCAL_SYMS_STRIPPED, \
               pe.FILE_HEADER.IMAGE_FILE_AGGRESIVE_WS_TRIM, \
               pe.FILE_HEADER.IMAGE_FILE_LARGE_ADDRESS_AWARE, \
               pe.FILE_HEADER.IMAGE_FILE_BYTES_REVERSED_LO, \
               pe.FILE_HEADER.IMAGE_FILE_32BIT_MACHINE, \
               pe.FILE_HEADER.IMAGE_FILE_DEBUG_STRIPPED, \
               pe.FILE_HEADER.IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, \
               pe.FILE_HEADER.IMAGE_FILE_NET_RUN_FROM_SWAP, \
               pe.FILE_HEADER.IMAGE_FILE_SYSTEM, \
               pe.FILE_HEADER.IMAGE_FILE_DLL, \
               pe.FILE_HEADER.IMAGE_FILE_UP_SYSTEM_ONLY, \
               pe.FILE_HEADER.IMAGE_FILE_BYTES_REVERSED_HI
               ]
        return [int(s) for s in tmp]

    def OPTIONAL_HEADER_DLLChar(self, pe):
        tmp = [
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, \
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, \
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NX_COMPAT, \
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_ISOLATION, \
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_SEH, \
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_BIND, \
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_WDM_DRIVER, \
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, \
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, \
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_APPCONTAINER, \
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_GUARD_CF
        ]
        return [int(s) for s in tmp]

    def Optional_header_ImageBase(self, ImageBase):
        result = 0
        if ImageBase % (64 * 1024) == 0 and ImageBase in [268435456, 65536, 4194304]:
            result = 1
        return result

    def Optional_header_SectionAlignment(self, SectionAlignment, FileAlignment):
        """This is boolean function and will return 0 or 1 based on condidtions
        that it SectionAlignment must be greater than or equal to FileAlignment
        """
        return int(SectionAlignment >= FileAlignment)

    def Optional_header_FileAlignment(self, SectionAlignment, FileAlignment):
        result = 0
        if SectionAlignment >= 512:
            if FileAlignment % 2 == 0 and FileAlignment in range(512, 65537):
                result = 1
        else:
            if FileAlignment == SectionAlignment:
                result = 1
        return result

    def Optional_header_SizeOfImage(self, SizeOfImage, SectionAlignment):
        return int(SizeOfImage % SectionAlignment == 0)

    def Optional_header_SizeOfHeaders(self, SizeOfHeaders, FileAlignment):
        return int(SizeOfHeaders % FileAlignment == 0)

    def check_packer(self, filepath):

        try:
            read_mal = open(filepath, "rb")
            read_data = read_mal.read()
            read_mal.close()

            matches = self.rules.match(data=read_data)

            result = []
            for match_list in matches:
                for match in str(match_list):
                    result.append(ord(match))
        except:
            return ['0', "0"]
        try:
            if matches == []:
                return ['0', "0"]
            else:
                return ['1', sum(result)]
        except:
            return ['0','0']

    def file_size_16(self,filepath):
        fp=open(filepath, 'rb')
        if len(fp.read()) % 16==0:
            fp.close()
            return ['0']
        elif (len(fp.read())+4)%16==0:
            fp.close()
            return ['0']
        else:
            fp.close()
            return ['1']


    def get_file_bytes_size(self, filepath):
        Bin_value = []
        if filepath != None:
            with open(filepath, 'rb') as file_object:
                data = file_object.read(1)
                while data != b"":
                    try:
                        Bin_value.append(ord(data))
                    except TypeError:
                        pass
                    data = file_object.read(1)

                return Bin_value, len(Bin_value)

    def cal_byteFrequency(self, byteArr, fileSize):
        freqList = []
        for b in range(256):
            ctr = 0
            for byte in byteArr:
                if byte == b:
                    ctr += 1
            freqList.append(float(ctr) / fileSize)
        return freqList

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

    def get_file_entropy(self, filepath):
        byteArr, fileSize = self.get_file_bytes_size(filepath)
        freqList = self.cal_byteFrequency(byteArr, fileSize)
        # Shannon entropy
        ent = 0.0
        for freq in freqList:
            if freq > 0:
                ent += - freq * math.log(freq, 2)

            # ent = -ent
        return [fileSize, ent]

    def get_resources(self,pe):
        resources = []
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            try:
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(resource_type, 'directory'):
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, 'directory'):
                                for resource_lang in resource_id.directory.entries:
                                    data = pe.get_data(resource_lang.data.struct.OffsetToData,
                                                       resource_lang.data.struct.Size)
                                    size = resource_lang.data.struct.Size
                                    entropy = self.get_entropy(data)

                                    resources.append([entropy, size])
            except Exception as e:
                return resources
        return resources



    ####################################################
    ###Extract Main PE Infos################################
    ####################################################
    def extract_dos_header(self, pe):
        IMAGE_DOS_HEADER_data = [0 for i in range(6)]
        try:
            IMAGE_DOS_HEADER_data = [
                pe.DOS_HEADER.e_cblp, \
                pe.DOS_HEADER.e_cp, \
                pe.DOS_HEADER.e_cparhdr, \
                pe.DOS_HEADER.e_maxalloc, \
                pe.DOS_HEADER.e_sp, \
                pe.DOS_HEADER.e_lfanew]
        except:
            print("PE Error")
        return IMAGE_DOS_HEADER_data

    def extract_file_header(self, pe):
        FILE_HEADER_data = [0 for i in range(3)]
        FILE_HEADER_char = []

        FILE_HEADER_data = [
            pe.FILE_HEADER.NumberOfSections, \
            self.file_creation_year(pe.FILE_HEADER.TimeDateStamp)]
        FILE_HEADER_char = self.FILE_HEADER_Char_boolean_set(pe)

        FILE_HEADER_data2 = [0 for i in range(5)]
        FILE_HEADER_data2 = [pe.FILE_HEADER.Machine, \
                             pe.FILE_HEADER.PointerToSymbolTable, \
                             pe.FILE_HEADER.NumberOfSymbols, \
                             pe.FILE_HEADER.SizeOfOptionalHeader, \
                             pe.FILE_HEADER.Characteristics]

        return FILE_HEADER_data + FILE_HEADER_char + FILE_HEADER_data2

    def extract_optional_header(self, pe):
        pe_dumps=pe.dump_dict()
        OPTIONAL_HEADER_data = [0 for i in range(20)]
        DLL_char = [0 for i in range(11)]
        OPTIONAL_HEADER_data2 = [0 for i in range(5)]

        OPTIONAL_HEADER_data = [
            pe_dumps["OPTIONAL_HEADER"]["MajorLinkerVersion"]["Value"], \
            pe_dumps["OPTIONAL_HEADER"]["MinorLinkerVersion"]["Value"], \
            pe_dumps["OPTIONAL_HEADER"]["SizeOfInitializedData"]["Value"],\
            pe_dumps["OPTIONAL_HEADER"]["SizeOfInitializedData"]["Value"], \
            pe_dumps["OPTIONAL_HEADER"]["SizeOfUninitializedData"]["Value"], \
            pe_dumps["OPTIONAL_HEADER"]["AddressOfEntryPoint"]["Value"], \
            pe_dumps["OPTIONAL_HEADER"]["BaseOfCode"]["Value"], \
            # Check the ImageBase for the condition
            self.Optional_header_ImageBase(pe_dumps["OPTIONAL_HEADER"]["ImageBase"]["Value"]), \
            # Checking for SectionAlignment condition
            self.Optional_header_SectionAlignment(pe_dumps["OPTIONAL_HEADER"]["SectionAlignment"]["Value"],
                                                  pe_dumps["OPTIONAL_HEADER"]["FileAlignment"]["Value"]), \
            # Checking for FileAlignment condition
            self.Optional_header_FileAlignment(pe_dumps["OPTIONAL_HEADER"]["SectionAlignment"]["Value"],
                                               pe_dumps["OPTIONAL_HEADER"]["FileAlignment"]["Value"]), \
            pe_dumps["OPTIONAL_HEADER"]["MajorOperatingSystemVersion"]["Value"], \
            pe_dumps["OPTIONAL_HEADER"]["MinorOperatingSystemVersion"]["Value"],\
            pe_dumps["OPTIONAL_HEADER"]["MajorImageVersion"]["Value"], \
            pe_dumps["OPTIONAL_HEADER"]["MinorImageVersion"]["Value"], \
            pe_dumps["OPTIONAL_HEADER"]["MajorSubsystemVersion"]["Value"], \
            pe_dumps["OPTIONAL_HEADER"]["MinorSubsystemVersion"]["Value"], \
            # Checking size of Image
            self.Optional_header_SizeOfImage(pe_dumps["OPTIONAL_HEADER"]["SizeOfImage"]["Value"], pe_dumps["OPTIONAL_HEADER"]["SectionAlignment"]["Value"]), \
            # Checking for size of headers
            self.Optional_header_SizeOfHeaders(pe_dumps["OPTIONAL_HEADER"]["SizeOfImage"]["Value"], pe_dumps["OPTIONAL_HEADER"]["SectionAlignment"]["Value"]), \
            pe_dumps["OPTIONAL_HEADER"]["CheckSum"]["Value"], \
            pe_dumps["OPTIONAL_HEADER"]["Subsystem"]["Value"], \
            pe_dumps["OPTIONAL_HEADER"]["NumberOfRvaAndSizes"]["Value"]]

        DLL_char = self.OPTIONAL_HEADER_DLLChar(pe)

        OPTIONAL_HEADER_data2 = [
            pe_dumps["OPTIONAL_HEADER"]["SizeOfStackReserve"]["Value"],\
            pe_dumps["OPTIONAL_HEADER"]["SizeOfStackCommit"]["Value"],\
            pe_dumps["OPTIONAL_HEADER"]["SizeOfHeapReserve"]["Value"],\
            pe_dumps["OPTIONAL_HEADER"]["SizeOfHeapCommit"]["Value"], \
            int(pe.OPTIONAL_HEADER.LoaderFlags == 0)]

        return OPTIONAL_HEADER_data + DLL_char + OPTIONAL_HEADER_data2

    ##################Section Info Extract#############################
    def get_count_suspicious_sections(self, pe):
        tmp = []
        benign_sections = set(
            ['.text', '.data', '.rdata', '.idata', '.edata', '.rsrc', '.bss', '.crt', '.tls', '.rsrc', '.crt', '.reloc',
             '.edata', '.sdata', '.ndata', '.itext', '.code', 'code'])
        for section in pe.sections:
            try:
                tmp.append(section.Name.decode().split('\x00')[0])
            except:
                continue
        non_sus_sections = len(set(tmp).intersection(benign_sections))
        result = [len(tmp) - non_sus_sections, non_sus_sections]
        return result

    def section_infos(self, pe):

        # 15 section lists
        section_dict = {}
        section_list = list(set(
            ['.text', '.data', '.rdata', '.idata', '.edata', '.rsrc', '.bss', '.crt', '.tls', '.rsrc', '.crt', '.reloc',
             '.edata', '.sdata', '.ndata', '.itext', '.code', 'code']))
        for i in section_list:
            section_dict[i] = [0 for i in range(21)]

        for section in pe.sections:
            try:
                Section_Name = section.Name.decode().split('\x00')[0]
            except:
                continue
            if Section_Name not in section_list: continue
            if section.IMAGE_SCN_TYPE_REG==True:IMAGE_SCN_TYPE_REG='0'
            else: IMAGE_SCN_TYPE_REG='1'
            if section.IMAGE_SCN_TYPE_COPY==True:IMAGE_SCN_TYPE_COPY='0'
            else:IMAGE_SCN_TYPE_COPY='1'
            if section.IMAGE_SCN_CNT_CODE==True:IMAGE_SCN_CNT_CODE='0'
            else:IMAGE_SCN_CNT_CODE='1'
            if section.IMAGE_SCN_CNT_INITIALIZED_DATA==True:IMAGE_SCN_CNT_INITIALIZED_DATA='0'
            else: IMAGE_SCN_CNT_INITIALIZED_DATA='1'
            if section.IMAGE_SCN_CNT_UNINITIALIZED_DATA==True:IMAGE_SCN_CNT_UNINITIALIZED_DATA='0'
            else:IMAGE_SCN_CNT_UNINITIALIZED_DATA='1'
            if section.IMAGE_SCN_LNK_OTHER==True:IMAGE_SCN_LNK_OTHER='0'
            else:IMAGE_SCN_LNK_OTHER='1'
            if section.IMAGE_SCN_LNK_INFO==True:IMAGE_SCN_LNK_INFO='0'
            else: IMAGE_SCN_LNK_INFO='1'
            if section.IMAGE_SCN_LNK_OVER==True:IMAGE_SCN_LNK_OVER='0'
            else:IMAGE_SCN_LNK_OVER='1'
            if section.IMAGE_SCN_LNK_REMOVE==True:IMAGE_SCN_LNK_REMOVE='0'
            else: IMAGE_SCN_LNK_REMOVE='1'
            if section.IMAGE_SCN_LNK_COMDAT==True:IMAGE_SCN_LNK_COMDAT='0'
            else:IMAGE_SCN_LNK_COMDAT='1'
            if section.IMAGE_SCN_MEM_PROTECTED==True:IMAGE_SCN_MEM_PROTECTED='0'
            else:IMAGE_SCN_MEM_PROTECTED='1'
            if section.IMAGE_SCN_NO_DEFER_SPEC_EXC==True:IMAGE_SCN_NO_DEFER_SPEC_EXC='0'
            else: IMAGE_SCN_NO_DEFER_SPEC_EXC='1'
            if section.IMAGE_SCN_MEM_LOCKED==True:IMAGE_SCN_MEM_LOCKED='0'
            else:IMAGE_SCN_MEM_LOCKED='1'
            if section.IMAGE_SCN_LNK_NRELOC_OVFL==True:IMAGE_SCN_LNK_NRELOC_OVFL='0'
            else:IMAGE_SCN_LNK_NRELOC_OVFL='1'
            if section.IMAGE_SCN_MEM_DISCARDABLE==True:IMAGE_SCN_MEM_DISCARDABLE='0'
            else:IMAGE_SCN_MEM_DISCARDABLE='1'
            if section.IMAGE_SCN_MEM_SHARED==True:IMAGE_SCN_MEM_SHARED='0'
            else:IMAGE_SCN_MEM_SHARED='1'
            if section.IMAGE_SCN_MEM_EXECUTE==True:IMAGE_SCN_MEM_EXECUTE='0'
            else:IMAGE_SCN_MEM_EXECUTE='1'
            if section.IMAGE_SCN_MEM_READ==True:IMAGE_SCN_MEM_READ='0'
            else:IMAGE_SCN_MEM_READ='1'
            if section.IMAGE_SCN_MEM_WRITE==True:IMAGE_SCN_MEM_WRITE='0'
            else:IMAGE_SCN_MEM_WRITE='1'

            section_dict[Section_Name] = [section.get_entropy(),
                                                                section.Characteristics,
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
                                                                IMAGE_SCN_MEM_WRITE]
        result = []
        for index in list(section_dict.values()):
            for colums in index:
                result.append(colums)

        return result


    def section_info2(self, pe):
        section_info2 = [0 for i in range(10)]
        try:
            entropy = list(map(lambda x: x.get_entropy(), pe.sections))
            raw_sizes = list(map(lambda x: x.SizeOfRawData, pe.sections))
            virtual_sizes = list(map(lambda x: x.Misc_VirtualSize, pe.sections))
            section_info2=[len(pe.sections),\
                                    sum(entropy) / float(len(entropy)),\
                                    min(entropy),\
                                    max(entropy),\
                                    sum(raw_sizes) / float(len(raw_sizes)),\
                                    min(raw_sizes),\
                                    max(raw_sizes),\
                                    sum(virtual_sizes) / float(len(virtual_sizes)),\
                                    min(virtual_sizes),\
                                    max(virtual_sizes)]
        except:
            pass
        return section_info2
    #############################################################

    #TLS DATA
    #############################################################
    def get_tls_data(self, pe):
        TLS_DATA = [0 for i in range(4)]

        try:
            TLS_DATA = [
                pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks,
                pe.DIRECTORY_ENTRY_TLS.struct.AddressOfIndex,
                pe.DIRECTORY_ENTRY_TLS.struct.EndAddressOfRawData,
                pe.DIRECTORY_ENTRY_TLS.struct.Characteristics
            ]
        except:
            pass
        return TLS_DATA
    #############################################################

    #File Info
    #############################################################
    def get_fileinfo(self, pe):

        StringFileInfo_list = [0 for i in range(13)]
        # getting Lower and
        try:
            FileVersionMS = pe.VS_FIXEDFILEINFO.FileVersionMS
            FileVersionLS = pe.VS_FIXEDFILEINFO.FileVersionLS
            ProductVersionMS = pe.VS_FIXEDFILEINFO.ProductVersionMS
            ProductVersionLS = pe.VS_FIXEDFILEINFO.ProductVersionLS

            StringFileInfo_list = [
                pe.VS_FIXEDFILEINFO.Signature,
                pe.VS_FIXEDFILEINFO.StrucVersion,
                pe.VS_FIXEDFILEINFO.FileFlagsMask,
                pe.VS_FIXEDFILEINFO.FileFlags,
                pe.VS_VERSIONINFO.Length,
                pe.VS_FIXEDFILEINFO.FileOS,
                pe.VS_VERSIONINFO.Type,
                pe.VS_FIXEDFILEINFO.FileType,
                pe.VS_FIXEDFILEINFO.FileSubtype,
                pe.VS_FIXEDFILEINFO.FileDateMS,
                pe.VS_FIXEDFILEINFO.FileDateLS,
                sum([FileVersionMS >> 16, FileVersionMS & 0xFFFF, FileVersionLS >> 16, FileVersionLS & 0xFFFF]),
                sum([ProductVersionMS >> 16, ProductVersionMS & 0xFFFF, ProductVersionLS >> 16,
                     ProductVersionLS & 0xFFFF])
            ]
        except:
            pass
        return StringFileInfo_list

    #############################################################


    #Imports
    #############################################################
    def Import(self, pe):

        imports_list = [0 for i in range(3)]
        try:
            imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
            imports_list=[len(pe.DIRECTORY_ENTRY_IMPORT),\
                                len(imports),\
                                len(list(filter(lambda x: x.name is None, imports)))]
        except:
            pass
        return imports_list

    #Export
    #############################################################
    def Export(self, pe):
        export_list = [0 for i in range(1)]
        try:
            exports = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
            export_list = [exports]
        except:
            pass
        return export_list
    #############################################################

    #Resource
    #############################################################
    def Resource(self, pe):
        resource_list = [0 for i in range(7)]
        resources= self.get_resources(pe)
        entropy = list(map(lambda x: x[0], resources))
        sizes = list(map(lambda x: x[1], resources))
        try:
            resource_list =[len(resources),\
                                sum(entropy)/float(len(entropy)),\
                                min(entropy),\
                                max(entropy),\
                                sum(sizes)/float(len(sizes)),\
                                min(sizes),\
                                max(sizes)]
        except:
            pass
        return resource_list
    #############################################################

    #Load  configuration size
    #############################################################
    def configuration_size(self, pe):

        configuration_list= [0 for i in range(1)]
        try:
            configuration_list=[pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size]
        except:
            pass
        return configuration_list


    #IMPORT Lists
    #############################################################
    def import_lists(self, files):
        import_dicts={'findresource': 0,
                                 'cryptacuirecontext': 0,
                                 'internetopenurl': 0,
                                 'ntsetinfomationprocess': 0,
                                 'getexitcodeprocess': 0,
                                 'getdc': 0,
                                 'gethostname': 0,
                                 'thread32next': 0,
                                 'cofreeunusedlibraries': 0,
                                 'system': 0,
                                 'internetconnecta': 0,
                                 'queryperformancecounter': 0,
                                 'variantchangetype': 0,
                                 'lookupprivilegevaluea': 0,
                                 '_acmdln': 0,
                                 'attachthreadinput': 0,
                                 'urldownloadtofile': 0,
                                 'internetopena': 0,
                                 'createservice': 0,
                                 'gettickcount': 0,
                                 'bitblt': 0,
                                 'setwindowshookex': 0,
                                 'findfirstfileexa': 0,
                                 'gethostbyname': 0,
                                 'thread32first': 0,
                                 'createremotethread': 0,
                                 'getenvironmentstrings': 0,
                                 'createtoolhelp32snapshot': 0,
                                 'sysstringlen': 0,
                                 '__vbaget3': 0,
                                 'recv': 0,
                                 'writeprocessmemory': 0,
                                 'getmodulefilenamea': 0,
                                 'createfilemapping': 0,
                                 'dllunregisterserver': 0,
                                 'getsystemdefaultlangid': 0,
                                 'createmutex': 0,
                                 'netschedulejobadd': 0,
                                 'shellexecute': 0,
                                 'virtuallocex': 0,
                                 'dllcanunloadnow': 0,
                                 'createfile': 0,
                                 '__unlock': 0,
                                 'queueuserapc': 0,
                                 'controlservice': 0,
                                 'excludecliprect': 0,
                                 'rtlcreateregistrykey': 0,
                                 'createprocess': 0,
                                 'wsastartup': 0,
                                 'regopenkey': 0,
                                 'registerhotkey': 0,
                                 'ntsetinformationprocess': 0,
                                 'samiconnect': 0,
                                 'findfirstfile': 0,
                                 'dllfunctioncall': 0,
                                 'loadlibrary': 0,
                                 'getprocaddress': 0,
                                 'ntquerydirectoryfile': 0,
                                 'connect': 0,
                                 'resumethread': 0,
                                 'callnexthookex': 0,
                                 'setthreadcontext': 0,
                                 'internetreadfile': 0,
                                 'winexec': 0,
                                 'loadresource': 0,
                                 'netshareenum': 0,
                                 'releasedc': 0,
                                 'dllonexit': 0,
                                 'getfullpathnamea': 0,
                                 'connectnamedpipe': 0,
                                 'getcurrentdirectory': 0,
                                 'bind': 0,
                                 'findnextfile': 0,
                                 'dllregisterserver': 0,
                                 'accept': 0,
                                 'adjusttokenprivileges': 0,
                                 'isntadmin': 0,
                                 'getmodulehandle': 0,
                                 'enumprocessmodules': 0,
                                 'readprocessmemory': 0,
                                 'shgetmalloc': 0,
                                 'enableexecuteprotectionsupport': 0,
                                 'virtualallocex': 0,
                                 'toolhelp32readprocessmemory': 0,
                                 'loadstringa': 0,
                                 'iswow64process': 0,
                                 'ntqueryinformationprocess': 0,
                                 'lstrcpya': 0,
                                 'setfiletime': 0,
                                 'cordllmain': 0,
                                 'free': 0,
                                 'peeknamepipe': 0,
                                 'openmutex': 0,
                                 'disablethreadlibrarycalls': 0,
                                 'checkremotedebuggerpresent': 0,
                                 'getforegroundwindow': 0,
                                 'getmodulefilename': 0,
                                 'getadapterinfo': 0,
                                 'virtualprotectex': 0,
                                 'getasynckeystate': 0,
                                 '__dllonexit': 0,
                                 'formatmessage': 0,
                                 'samqueryinformationuse': 0,
                                 'gettemppath': 0,
                                 'getadaptersinfo': 0,
                                 '_iob': 0,
                                 'samqueryinfomationuse': 0,
                                 'mmgetsystemroutineaddress': 0,
                                 'findwindow': 0,
                                 'dllinstall': 0,
                                 'lsaenumeratelogonsessions': 0,
                                 'inet_addr': 0,
                                 'process32first': 0,
                                 'cocreateinstance': 0,
                                 'openprocess': 0,
                                 'module32next': 0,
                                 'openscmanager': 0,
                                 'mapvirtualkey': 0,
                                 'certopensystemstore': 0,
                                 'openprocesstoken': 0,
                                 'select': 0,
                                 'wow64disablewow64fsredirection': 0,
                                 'enumprocesses': 0,
                                 'internetwritefile': 0,
                                 'isdebuggerpresent': 0,
                                 'outputdebugstring': 0,
                                 'deviceiocontrol': 0,
                                 'wlxloggedonsas': 0,
                                 'getkeystate': 0,
                                 'send': 0,
                                 'getuserdefaultlangid': 0,
                                 'getwindowsdirectory': 0,
                                 'wsaioctl': 0,
                                 'getversionex': 0,
                                 'ftpputfile': 0,
                                 'module32first': 0,
                                 'internetopen': 0,
                                 'startservicectrldispatcher': 0,
                                 'getstartupinfo': 0,
                                 'oleinitialize': 0,
                                 'samigetprivatedata': 0,
                                 'isvalidlocale': 0,
                                 'cryptacquirecontext': 0,
                                 'mapviewoffile': 0,
                                 'ldrloaddll': 0,
                                 'rtlwriteregistryvalue': 0,
                                 'getlocaleinfoa': 0,
                                 'sfcterminatewatcherthread': 0,
                                 'getfilesize': 0,
                                 'interlockedincrement': 0,
                                 'suspendthread': 0,
                                 'variantcopyind': 0,
                                 'peeknamedpipe': 0,
                                 'process32next': 0,
                                 'getthreadcontext': 0,
                                 'internetclosehandle': 0,
                                 'dllgetclassobject': 0,
                                 'widechartomultibyte': 0,
                                 '_coreexemain': 0}
        import_lists = list(import_dicts.keys())

        pe=pefile.PE(files)

        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:

                    if imp.name.decode().lower() in import_lists:
                        import_dicts[imp.name.decode().lower()]+=1
        except:
            pass
        pe.close()

        fp = open(files, 'rb')
        bindata = fp.read()
        bindata = str(bindata)
        fp.close()
        regex=None
        if regex is None:
            regex = re.compile("[\w\~\!\@\#\$\%\^\&\*\(\)\-_=\+ \/\.\,\?\s]{4,}")
            BINDATA_RESULT = regex.findall(bindata)

        for BINDATA in BINDATA_RESULT:
            if len(BINDATA) > 3000:
                continue

            regex2 = re.compile('([x\d]+)|([\D]+)')

            BINDATA_REGEX2 = regex2.search(BINDATA)
            if BINDATA_REGEX2.group(1) == None:
                if len(BINDATA_REGEX2.group(2)) > 6:
                    if BINDATA_REGEX2.group(2).lower() in import_lists:
                        import_dicts[BINDATA_REGEX2.group(2).lower()] += 1
                    elif BINDATA_REGEX2.group(2)[:-1].lower() in  import_lists:
                        import_dicts[BINDATA_REGEX2.group(2).lower()[:-1]] += 1


            elif BINDATA_REGEX2.group(1) != None:

                regex2 = re.compile('([x\d]+)([\D]+)')
                BINDATA_REGEX2 = regex2.search(BINDATA)
                if BINDATA_REGEX2 == None: continue
                if len(BINDATA_REGEX2.group(2)) > 6:
                    if BINDATA_REGEX2.group(2).lower() in import_lists:
                        import_dicts[BINDATA_REGEX2.group(2).lower()] += 1
                    elif BINDATA_REGEX2.group(2)[:-1].lower() in import_lists:
                        import_dicts[BINDATA_REGEX2.group(2).lower()[:-1]] += 1

        return list(import_dicts.values())

    #Certificate Get Sign
    #############################################################
    def extractPKCS7(self,fname):
        pkcs=[0 for i in range(1)]

        try:
            totsize = os.path.getsize(fname)
            ape = pefile.PE(fname, fast_load=True)
            ape.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']])
            sigoff = 0
            siglen = 0
            for s in ape.__structures__:
                if s.name == 'IMAGE_DIRECTORY_ENTRY_SECURITY':
                    sigoff = s.VirtualAddress
                    siglen = s.Size
            ape.close()
            if sigoff < totsize:
                f = open(fname, 'rb')
                f.seek(sigoff)
                thesig = f.read(siglen)
                f.close()

                if 'sign' in str(thesig[8:]).lower() or  'root' in str(thesig[8:]).lower() or 'global' in str(thesig[8:]).lower():
                    pkcs[0] = 1
                    return pkcs
                else:
                    pkcs[0] = 0
                    return pkcs
        except:
            pkcs[0] = 0
            return pkcs

        #############################################################

#Get string ngrams
#############################################################

def get_entropy(data):
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

#mutex_file = open('C:\\Users\\vm\\Desktop\\Breakers\\binary-diffing-tool\\Main_engine\\ML\\mutex_strings_lists.txt', 'r')
mutex_file = open(os.getcwd()+"\\Main_engine\\ML\\"+"mutex_strings_lists.txt", 'r')
mutex_list = [line[:-1] for line in mutex_file]

#mutex_file2 = open('C:\\Users\\vm\\Desktop\\Breakers\\binary-diffing-tool\\Main_engine\\ML\\win32api_alphabet.txt', 'r')
mutex_file2 = open(os.getcwd()+"\\Main_engine\\ML\\"+'win32api_alphabet.txt', 'r')
mutex_list2 = [line2[:-1] for line2 in mutex_file2]

mutex_file3 = open(os.getcwd()+"\\Main_engine\\ML\\"+'win32api_category.txt', 'r')
mutex_list3 = [line3[:-1] for line3 in mutex_file3]

ipaddress_re = re.compile('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
email_re = re.compile('^[a-zA-Z0-9+-_.]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
url_re = re.compile(
    r'^(?:(?:https|ftp|www)://)(?:\S+(?::\S*)?@)?(?:(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,})))(?::\d{2,5})?(?:/[^\s]*)?$')

mutex1 = re.compile("[@]")
mutex2 = re.compile("[?]")
mutex3 = re.compile("[=]")
mutex4 = re.compile("[\w]")
mutex5 = re.compile("[\W]")

find_string_list=['ransome','vpn','adware','tracking','browser','hijac',\
                  'crime','hack','tool','crack','keygen','trojan','worm','virus','autorun',\
                  'download','power','shell','url','root','payload']

Registry_list=['hidden', 'currentversion', 'hkcu', 'hklm', 'explorer', 'showsuperhidden', 'windows nt',\
               'winlogon', 'userinit', 'run', 'runonce', 'policies', 'internet explorer', 'tcpip', 'controlset001', \
               'winsock2', 'wscsvc', 'enablelua', 'sharedaccess', 'firewallpolicy', 'standardprofile', 'authorizedapplications',\
               'donotallowexceptions', 'enablefirewall', 'enabledcom', 'security center', 'antivirusdisablenotify',\
               'firewalldisablenotify', 'antivirusoverride', 'currentcontrolset', 'restrictanonymous', 'control panel', \
               'activedesktop', 'runservices', 'inprocserver32', 'remoteaccess', 'browser helper objects', 'safeboot',\
               'superhidden', 'internet explorer']

wmi_list=['systemdrive','userprofile','temp','tmp','appdata','public','alluserprofile','programdata',\
          'prgramfiles','commonprogramfiles','systemroot','windir','comspec','psmodulepath','userdomain',\
          'username','computername','os','processor_architecture','processor_identifier','processor_level',\
          'processor_revision','number_of_processors']

cmd_list=['cmd', 'exe', 'dll', 'assoc', 'attrib', 'call', 'del',\
          'dir', 'driverquery', 'mkdir', 'prompt', 'rename', 'set', 'schtasks',\
          'shutdown', 'systeminfo', 'tasklist', 'taskkill', 'whoami', 'wmic', 'netstat',\
          'net start', 'net share','ipconfig','net time','qprocess','query','net use',\
          'net user','net view','sc','reg']

powershell_list=['location','write-output','get-executionpolicy','securitycenter',\
                 'antivirusproduct','get-wmiobject','win32_computersystem',\
                 'get-childltem','env:os','comspec','appdata','alluserprofile',\
                 'computername','localappdata','userprofile','wind hidden',\
                 'bypass','downloadfile','webclient','downloadstring','bitstransfer',\
                 'invoke','shellexecute','start-process','scriptblock','filename',\
                 'encodedcommand','tobase64string','get-content','gzipstream','msfvenom']

def exstrings(FILENAME,regex=None):
    string_dics={'et':0,
                        'ge':0,
                        'er':0,
                        'te':0,
                        'on':0,
                        'in':0,
                        'ti':0,
                        're':0,
                        'me':0,
                        'st':0,
                        'en':0,
                        'le':0,
                        'to':0,
                        'es':0,
                        'ro':0,
                        'co':0,
                        'nt':0,
                        'ow':0,
                        'ad':0,
                        'lo':0,
                        'se':0,
                        'do':0,
                        'at':0,
                        'ol':0,
                        'ta':0,
                        'tr':0,
                        'th':0,
                        'ri':0,
                        'io':0,
                        'em':0,
                        'or':0,
                        'tt':0,
                        'de':0,
                        'al':0,
                        'ur':0,
                        'na':0,
                        'ce':0,
                        'it':0,
                        'ed':0,
                        'oo':0,
                        'wn':0,
                        'oa':0,
                        'an':0,
                        'nl':0,
                        'ct':0,
                        'ar':0,
                        'ma':0,
                        'ec':0,
                        'am':0,
                        'si':0,
                        'he':0,
                        'om':0,
                        'ex':0,
                        'ic':0,
                        'nd':0,
                        'il':0,
                        'll':0,
                        'ne':0,
                        've':0,
                        'so':0,
                        'ng':0,
                        'ns':0,
                        'ag':0,
                        'is':0,
                        'ac':0,
                        'ra':0,
                        'pe':0,
                        'pa':0,
                        'fi':0,
                        'gt':0,
                        'li':0,
                        'tk':0,
                        'ts':0,
                        'ss':0,
                        'di':0,
                        'rt':0,
                        'ou':0,
                        'cr':0,
                        'pr':0,
                        'os':0,
                        'od':0,
                        'tp':0,
                        'id':0,
                        'wi':0,
                        'ev':0,
                        'ca':0,
                        'fo':0,
                        'ty':0,
                        'el':0,
                        'cu':0,
                        'ls':0,
                        'as':0,
                        'oc':0,
                        'rl':0,
                        'ea':0,
                        'po':0,
                        'ip':0,
                        'ut':0,
                        'un':0,
                        'ww':0}

    string_4_dics={
                                'Comp':0,
                                'Syst':0,
                                'Attr':0,
                                'Obje':0,
                                'Stat':0,
                                'ctio':0,
                                'ribu':0,
                                'Read':0,
                                'roce':0}

    importlists = []

    ipaddress_count = [0 for i in range(1)]
    email_address_count= [0 for i in range(1)]
    url_count= [0 for i in range(1)]
    mal_strIng_count=[0 for i in range(1)]

    wmi_count = [0 for i in range(1)]
    registry_str_count=[0 for i in range(1)]
    cmd_count = [0 for i in range(1)]
    power_shell_count = [0 for i in range(1)]


    try:
        PF = pefile.PE(FILENAME)

        for entry in PF.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                importlists.append(imp.name.decode())
        PF.close()
    except:
        pass

    fp = open(FILENAME, 'rb')
    bindata = fp.read()
    entropys=get_entropy(bindata)
    bindata=str(bindata )
    fp.close()

    if regex is None:
        regex = re.compile("[\w\~\!\@\#\$\%\^\&\*\(\)\-_=\+ \/\.\,\?\s]{4,}")
        BINDATA_RESULT = regex.findall(bindata)

    for BINDATA in BINDATA_RESULT:
        if len(BINDATA) > 3000:
            continue

        regex2 = re.compile('([x\d]+)|([\D]+)')

        BINDATA_REGEX2 = regex2.search(BINDATA)
        if BINDATA_REGEX2.group(1) == None:
            if len(BINDATA_REGEX2.group(2)) > 6:
                if BINDATA_REGEX2.group(2) in importlists or BINDATA_REGEX2.group(2)[:-1] in importlists:
                    continue
                elif BINDATA_REGEX2.group(2) in mutex_list or BINDATA_REGEX2.group(2)[:-1] in mutex_list:
                    continue
                elif BINDATA_REGEX2.group(2) in mutex_list2 or BINDATA_REGEX2.group(2)[:-1] in mutex_list2:
                    continue
                elif BINDATA_REGEX2.group(2) in mutex_list3 or BINDATA_REGEX2.group(2)[:-1] in mutex_list3:
                    continue

                    # mutext strings
                if 'PAD' in BINDATA_REGEX2.group(2)[:-1]:
                    continue
                elif '__' in BINDATA_REGEX2.group(2)[:-1]:
                    continue
                elif '$' in BINDATA_REGEX2.group(2)[:-1]:
                    continue
                elif len(mutex1.findall(BINDATA_REGEX2.group(2)[:-1])) > 1:
                    continue
                elif len(mutex2.findall(BINDATA_REGEX2.group(2)[:-1])) > 2:
                    continue
                elif len(mutex3.findall(BINDATA_REGEX2.group(2)[:-1])) > 2:
                    continue
                elif len(set(mutex4.findall(BINDATA_REGEX2.group(2)[:-1]))) <= 7:
                    continue
                elif len(set(mutex5.findall(BINDATA_REGEX2.group(2)[:-1]))) > 2:
                    continue

                string_2gram = zip(BINDATA_REGEX2.group(2).lower(), BINDATA_REGEX2.group(2).lower()[1:])
                for grams in string_2gram:
                    join_str = ''.join(grams)
                    if join_str in string_dics.keys():
                        try:
                            string_dics[join_str] += 1
                        except:
                            string_dics[join_str] = 1

                for index in range(len(BINDATA_REGEX2.group(2).lower()) - 4 + 1):
                    join_str = BINDATA_REGEX2.group(2).lower()[index:index + 4]
                    if join_str in string_4_dics.keys():
                        try:
                            string_4_dics[join_str] += 1
                        except:
                            string_4_dics[join_str] = 1

                if len(ipaddress_re.findall(BINDATA_REGEX2.group(2)[:-1])) >= 1:
                    ipaddress_count[0]+=1
                    continue
                elif len(email_re.findall(BINDATA_REGEX2.group(2)[:-1])) >= 1:
                    email_address_count[0]+=1
                    continue
                elif len(url_re.findall(BINDATA_REGEX2.group(2)[:-1])) >= 1:
                    url_count[0]+=1
                    continue

                for find_string in find_string_list:
                    if find_string in  BINDATA_REGEX2.group(2)[:-1].lower():
                        mal_strIng_count[0]+=1

                for find_string in wmi_list:
                    if find_string in  BINDATA_REGEX2.group(2)[:-1].lower():
                        wmi_count[0]+=1

                for find_string in Registry_list:
                    if find_string in  BINDATA_REGEX2.group(2)[:-1].lower():
                        registry_str_count[0]+=1

                for find_string in cmd_list:
                    if find_string in  BINDATA_REGEX2.group(2)[:-1].lower():
                        cmd_count[0]+=1

                for find_string in powershell_list:
                    if find_string in  BINDATA_REGEX2.group(2)[:-1].lower():
                        power_shell_count[0]+=1


        elif BINDATA_REGEX2.group(1) != None:
            regex2 = re.compile('([x\d]+)([\D]+)')
            BINDATA_REGEX2 = regex2.search(BINDATA)
            if BINDATA_REGEX2==None:continue
            if len(BINDATA_REGEX2.group(2))>6:
                if BINDATA_REGEX2.group(2) in importlists or BINDATA_REGEX2.group(2)[:-1] in importlists:
                    continue
                elif BINDATA_REGEX2.group(2) in mutex_list or BINDATA_REGEX2.group(2)[:-1] in mutex_list:
                    continue
                elif BINDATA_REGEX2.group(2) in mutex_list2 or BINDATA_REGEX2.group(2)[:-1] in mutex_list2:
                    continue
                elif BINDATA_REGEX2.group(2) in mutex_list3 or BINDATA_REGEX2.group(2)[:-1] in mutex_list3:
                    continue

                    # mutext strings
                if 'PAD' in BINDATA_REGEX2.group(2)[:-1]:
                    continue
                elif '__' in BINDATA_REGEX2.group(2)[:-1]:
                    continue
                elif '$' in BINDATA_REGEX2.group(2)[:-1]:
                    continue
                elif len(mutex1.findall(BINDATA_REGEX2.group(2)[:-1])) > 1:
                    continue
                elif len(mutex2.findall(BINDATA_REGEX2.group(2)[:-1])) > 2:
                    continue
                elif len(mutex3.findall(BINDATA_REGEX2.group(2)[:-1])) > 2:
                    continue
                elif len(set(mutex4.findall(BINDATA_REGEX2.group(2)[:-1]))) <= 7:
                    continue
                elif len(set(mutex5.findall(BINDATA_REGEX2.group(2)[:-1]))) > 2:
                    continue

                string_2gram = zip(BINDATA_REGEX2.group(2).lower(), BINDATA_REGEX2.group(2).lower()[1:])
                for grams in string_2gram:
                    join_str = ''.join(grams)
                    if join_str in string_dics.keys():
                        try:
                            string_dics[join_str] += 1
                        except:
                            string_dics[join_str] = 1

                for index in range(len(BINDATA_REGEX2.group(2).lower()) - 4 + 1):
                    join_str = BINDATA_REGEX2.group(2).lower()[index:index + 4]
                    if join_str in string_4_dics.keys():
                        try:
                            string_4_dics[join_str] += 1
                        except:
                            string_4_dics[join_str] = 1

                if len(ipaddress_re.findall(BINDATA_REGEX2.group(2)[:-1])) >= 1:
                    ipaddress_count[0]+=1
                    continue
                elif len(email_re.findall(BINDATA_REGEX2.group(2)[:-1])) >= 1:
                    email_address_count[0]+=1
                    continue
                elif len(url_re.findall(BINDATA_REGEX2.group(2)[:-1])) >= 1:
                    url_count[0]+=1
                    continue

                for find_string in find_string_list:
                    if find_string in  BINDATA_REGEX2.group(2)[:-1].lower():
                        mal_strIng_count[0]+=1

                for find_string in wmi_list:
                    if find_string in  BINDATA_REGEX2.group(2)[:-1].lower():
                        wmi_count[0]+=1

                for find_string in Registry_list:
                    if find_string in  BINDATA_REGEX2.group(2)[:-1].lower():
                        registry_str_count[0]+=1

                for find_string in cmd_list:
                    if find_string in  BINDATA_REGEX2.group(2)[:-1].lower():
                        cmd_count[0]+=1

                for find_string in powershell_list:
                    if find_string in  BINDATA_REGEX2.group(2)[:-1].lower():
                        power_shell_count[0]+=1

    fp.close()

    result=list(string_dics.values())+ipaddress_count+email_address_count+url_count+mal_strIng_count+wmi_count+registry_str_count+cmd_count+power_shell_count+[entropys]+list(string_4_dics.values())

    return result


#############################################################


result_dicts={'Unknown': 0,
                     'Import0': 0,
                     'Linker510': 0,
                     'Cvtomf510': 0,
                     'Linker600': 0,
                     'Cvtomf600': 0,
                     'Cvtres500': 0,
                     'Utc11_Basic': 0,
                     'Utc11_C': 0,
                     'Utc12_Basic': 0,
                     'Utc12_C': 0,
                     'Utc12_CPP': 0,
                     'AliasObj60': 0,
                     'VisualBasic60': 0,
                     'Masm613': 0,
                     'Masm710': 0,
                     'Linker511': 0,
                     'Cvtomf511': 0,
                     'Masm614': 0,
                     'Linker512': 0,
                     'Cvtomf512': 0,
                     'Utc12_C_Std': 0,
                     'Utc12_CPP_Std': 0,
                     'Utc12_C_Book': 0,
                     'Utc12_CPP_Book': 0,
                     'Implib700': 0,
                     'Cvtomf700': 0,
                     'Utc13_Basic': 0,
                     'Utc13_C': 0,
                     'Utc13_CPP': 0,
                     'Linker610': 0,
                     'Cvtomf610': 0,
                     'Linker601': 0,
                     'Cvtomf601': 0,
                     'Utc12_1_Basic': 0,
                     'Utc12_1_C': 0,
                     'Utc12_1_CPP': 0,
                     'Linker620': 0,
                     'Cvtomf620': 0,
                     'AliasObj70': 0,
                     'Linker621': 0,
                     'Cvtomf621': 0,
                     'Masm615': 0,
                     'Utc13_LTCG_C': 0,
                     'Utc13_LTCG_CPP': 0,
                     'Masm620': 0,
                     'ILAsm100': 0,
                     'Utc12_2_Basic': 0,
                     'Utc12_2_C': 0,
                     'Utc12_2_CPP': 0,
                     'Utc12_2_C_Std': 0,
                     'Utc12_2_CPP_Std': 0,
                     'Utc12_2_C_Book': 0,
                     'Utc12_2_CPP_Book': 0,
                     'Implib622': 0,
                     'Cvtomf622': 0,
                     'Cvtres501': 0,
                     'Utc13_C_Std': 0,
                     'Utc13_CPP_Std': 0,
                     'Cvtpgd1300': 0,
                     'Linker622': 0,
                     'Linker700': 0,
                     'Export622': 0,
                     'Export700': 0,
                     'Masm700': 0,
                     'Utc13_POGO_I_C': 0,
                     'Utc13_POGO_I_CPP': 0,
                     'Utc13_POGO_O_C': 0,
                     'Utc13_POGO_O_CPP': 0,
                     'Cvtres700': 0,
                     'Cvtres710p': 0,
                     'Linker710p': 0,
                     'Cvtomf710p': 0,
                     'Export710p': 0,
                     'Implib710p': 0,
                     'Masm710p': 0,
                     'Utc1310p_C': 0,
                     'Utc1310p_CPP': 0,
                     'Utc1310p_C_Std': 0,
                     'Utc1310p_CPP_Std': 0,
                     'Utc1310p_LTCG_C': 0,
                     'Utc1310p_LTCG_CPP': 0,
                     'Utc1310p_POGO_I_C': 0,
                     'Utc1310p_POGO_I_CPP': 0,
                     'Utc1310p_POGO_O_C': 0,
                     'Utc1310p_POGO_O_CPP': 0,
                     'Linker624': 0,
                     'Cvtomf624': 0,
                     'Export624': 0,
                     'Implib624': 0,
                     'Linker710': 0,
                     'Cvtomf710': 0,
                     'Export710': 0,
                     'Implib710': 0,
                     'Cvtres710': 0,
                     'Utc1310_C': 0,
                     'Utc1310_CPP': 0,
                     'Utc1310_C_Std': 0,
                     'Utc1310_CPP_Std': 0,
                     'Utc1310_LTCG_C': 0,
                     'Utc1310_LTCG_CPP': 0,
                     'Utc1310_POGO_I_C': 0,
                     'Utc1310_POGO_I_CPP': 0,
                     'Utc1310_POGO_O_C': 0,
                     'Utc1310_POGO_O_CPP': 0,
                     'AliasObj710': 0,
                     'AliasObj710p': 0,
                     'Cvtpgd1310': 0,
                     'Cvtpgd1310p': 0,
                     'Utc1400_C': 0,
                     'Utc1400_CPP': 0,
                     'Utc1400_C_Std': 0,
                     'Utc1400_CPP_Std': 0,
                     'Utc1400_LTCG_C': 0,
                     'Utc1400_LTCG_CPP': 0,
                     'Utc1400_POGO_I_C': 0,
                     'Utc1400_POGO_I_CPP': 0,
                     'Utc1400_POGO_O_C': 0,
                     'Utc1400_POGO_O_CPP': 0,
                     'Cvtpgd1400': 0,
                     'Linker800': 0,
                     'Cvtomf800': 0,
                     'Export800': 0,
                     'Implib800': 0,
                     'Cvtres800': 0,
                     'Masm800': 0,
                     'AliasObj800': 0,
                     'PhoenixPrerelease': 0,
                     'Utc1400_CVTCIL_C': 0,
                     'Utc1400_CVTCIL_CPP': 0,
                     'Utc1400_LTCG_MSIL': 0,
                     'Utc1500_C': 0,
                     'Utc1500_CPP': 0,
                     'Utc1500_C_Std': 0,
                     'Utc1500_CPP_Std': 0,
                     'Utc1500_CVTCIL_C': 0,
                     'Utc1500_CVTCIL_CPP': 0,
                     'Utc1500_LTCG_C': 0,
                     'Utc1500_LTCG_CPP': 0,
                     'Utc1500_LTCG_MSIL': 0,
                     'Utc1500_POGO_I_C': 0,
                     'Utc1500_POGO_I_CPP': 0,
                     'Utc1500_POGO_O_C': 0,
                     'Utc1500_POGO_O_CPP': 0,
                     'Cvtpgd1500': 0,
                     'Linker900': 0,
                     'Export900': 0,
                     'Implib900': 0,
                     'Cvtres900': 0,
                     'Masm900': 0,
                     'AliasObj900': 0,
                     'Resource900': 0,
                     'AliasObj1000': 0,
                     'Cvtres1000': 0,
                     'Export1000': 0,
                     'Implib1000': 0,
                     'Linker1000': 0,
                     'Masm1000': 0,
                     'Utc1600_C': 0,
                     'Utc1600_CPP': 0,
                     'Utc1600_CVTCIL_C': 0,
                     'Utc1600_CVTCIL_CPP': 0,
                     'Utc1600_LTCG_C ': 0,
                     'Utc1600_LTCG_CPP': 0,
                     'Utc1600_LTCG_MSIL': 0,
                     'Utc1600_POGO_I_C': 0,
                     'Utc1600_POGO_I_CPP': 0,
                     'Utc1600_POGO_O_C': 0,
                     'Utc1600_POGO_O_CPP': 0,
                     'Linker1010': 0,
                     'Export1010': 0,
                     'Implib1010': 0,
                     'Cvtres1010': 0,
                     'Masm1010': 0,
                     'AliasObj1010': 0,
                     'AliasObj1100': 0,
                     'Cvtres1100': 0,
                     'Export1100': 0,
                     'Implib1100': 0,
                     'Linker1100': 0,
                     'Masm1100': 0,
                     'Utc1700_C': 0,
                     'Utc1700_CPP': 0,
                     'Utc1700_CVTCIL_C': 0,
                     'Utc1700_CVTCIL_CPP': 0,
                     'Utc1700_LTCG_C ': 0,
                     'Utc1700_LTCG_CPP': 0,
                     'Utc1700_LTCG_MSIL': 0,
                     'Utc1700_POGO_I_C': 0,
                     'Utc1700_POGO_I_CPP': 0,
                     'Utc1700_POGO_O_C': 0,
                     'Utc1700_POGO_O_CPP': 0,
                     'etc':0}


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

class richheader:
    def __init__(self, fp):
        self.info = []
        self.clear_data = []
        self.prodid = []
        self.xorkey = ""
        try:
            data = fp.read()
            end = struct.unpack('<I', data[0x3c:0x40])[0]
            data = data[0x80:end]
            rich_addr = data.find(b'Rich')
            self.xorkey = struct.unpack('<I', data[rich_addr + 4:rich_addr + 8])[0]
            self.data = data[:rich_addr]
            for i in range(16, rich_addr, 8):
                key = struct.unpack("<L", self.data[i:i + 4])[0] ^ self.xorkey
                count = struct.unpack("<L", self.data[i + 4:i + 8])[0] ^ self.xorkey
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
    results=[0 for i in range(197)]
    RichHeader_dic = {'prodid': np.nan,
                      "xorkey": np.nan,
                      "sample_clear_data": np.nan,
                      "build": np.nan,
                      "count": np.nan
                      }
    try:
        open_file = open(filename, 'rb')
        sample_rich_information = richheader(open_file)
        xorkey = sample_rich_information.xorkey
        if xorkey=='':xorkey=0
        RichHeader_dic['xorkey'] = xorkey

        prodid = sample_rich_information.return_prodid()
        for i in prodid:
            if (i <= 216):
                result_dicts[PRODID_MAP[i]]+=1
            elif (i > 216):
                result_dicts['etc'] += 1

        RichHeader_dic['prodid'] = result_dicts

        sample_clear_data = sample_rich_information.return_clear_data()
        # print(sample_clear_data)
        sample_clear_data = sum([int(i, 16) for i in sample_clear_data])
        RichHeader_dic['sample_clear_data'] = sample_clear_data

        build = sample_rich_information.return_build()
        build = sum([int(i, 16) for i in build])
        RichHeader_dic['build'] = build

        count = sample_rich_information.return_count()
        count = sum([int(i, 16) for i in count])
        RichHeader_dic['count'] = count

        open_file.close()

        results=list(result_dicts.values())+[sample_clear_data]+[xorkey]+[build]+[count]
    except:
        return results
    return results




section_characteristics = [
    ('IMAGE_SCN_TYPE_REG', 0x00000000),  # reserved
    ('IMAGE_SCN_TYPE_DSECT', 0x00000001),  # reserved
    ('IMAGE_SCN_TYPE_NOLOAD', 0x00000002),  # reserved
    ('IMAGE_SCN_TYPE_GROUP', 0x00000004),  # reserved
    ('IMAGE_SCN_TYPE_NO_PAD', 0x00000008),  # reserved
    ('IMAGE_SCN_TYPE_COPY', 0x00000010),  # reserved

    ('IMAGE_SCN_CNT_CODE', 0x00000020),
    ('IMAGE_SCN_CNT_INITIALIZED_DATA', 0x00000040),
    ('IMAGE_SCN_CNT_UNINITIALIZED_DATA', 0x00000080),

    ('IMAGE_SCN_LNK_OTHER', 0x00000100),
    ('IMAGE_SCN_LNK_INFO', 0x00000200),
    ('IMAGE_SCN_LNK_OVER', 0x00000400),  # reserved
    ('IMAGE_SCN_LNK_REMOVE', 0x00000800),
    ('IMAGE_SCN_LNK_COMDAT', 0x00001000),

    ('IMAGE_SCN_MEM_PROTECTED', 0x00004000),  # obsolete
    ('IMAGE_SCN_NO_DEFER_SPEC_EXC', 0x00004000),
    ('IMAGE_SCN_GPREL', 0x00008000),
    ('IMAGE_SCN_MEM_FARDATA', 0x00008000),
    ('IMAGE_SCN_MEM_SYSHEAP', 0x00010000),  # obsolete
    ('IMAGE_SCN_MEM_PURGEABLE', 0x00020000),
    ('IMAGE_SCN_MEM_16BIT', 0x00020000),
    ('IMAGE_SCN_MEM_LOCKED', 0x00040000),
    ('IMAGE_SCN_MEM_PRELOAD', 0x00080000),

    ('IMAGE_SCN_ALIGN_1BYTES', 0x00100000),
    ('IMAGE_SCN_ALIGN_2BYTES', 0x00200000),
    ('IMAGE_SCN_ALIGN_4BYTES', 0x00300000),
    ('IMAGE_SCN_ALIGN_8BYTES', 0x00400000),
    ('IMAGE_SCN_ALIGN_16BYTES', 0x00500000),  # default alignment
    ('IMAGE_SCN_ALIGN_32BYTES', 0x00600000),
    ('IMAGE_SCN_ALIGN_64BYTES', 0x00700000),
    ('IMAGE_SCN_ALIGN_128BYTES', 0x00800000),
    ('IMAGE_SCN_ALIGN_256BYTES', 0x00900000),
    ('IMAGE_SCN_ALIGN_512BYTES', 0x00A00000),
    ('IMAGE_SCN_ALIGN_1024BYTES', 0x00B00000),
    ('IMAGE_SCN_ALIGN_2048BYTES', 0x00C00000),
    ('IMAGE_SCN_ALIGN_4096BYTES', 0x00D00000),
    ('IMAGE_SCN_ALIGN_8192BYTES', 0x00E00000),
    ('IMAGE_SCN_ALIGN_MASK', 0x00F00000),

    ('IMAGE_SCN_LNK_NRELOC_OVFL', 0x01000000),
    ('IMAGE_SCN_MEM_DISCARDABLE', 0x02000000),
    ('IMAGE_SCN_MEM_NOT_CACHED', 0x04000000),
    ('IMAGE_SCN_MEM_NOT_PAGED', 0x08000000),
    ('IMAGE_SCN_MEM_SHARED', 0x10000000),
    ('IMAGE_SCN_MEM_EXECUTE', 0x20000000),
    ('IMAGE_SCN_MEM_READ', 0x40000000),
    ('IMAGE_SCN_MEM_WRITE', 0x80000000)]

SECTION_CHARACTERISTICS = dict([(e[1], e[0]) for e in section_characteristics] + section_characteristics)

def retrieve_flags(flag_dict, flag_filter):
    """Read the flags from a dictionary and return them in a usable form.

    Will return a list of (flag, value) for all flags in "flag_dict"
    matching the filter "flag_filter".
    """

    return [(f[0], f[1]) for f in list(flag_dict.items()) if
            isinstance(f[0], (str, bytes)) and f[0].startswith(flag_filter)]


section_flags = retrieve_flags(SECTION_CHARACTERISTICS, 'IMAGE_SCN_')


def opcode_info_get(sample_path):
        result_opcoded_count_dict={'MOV': 0,
                                                         'LEA': 0,
                                                         'ANDL': 0,
                                                         'JE': 0,
                                                         'ADD': 0,
                                                         'SBB': 0,
                                                         'SUB': 0,
                                                         'INT3': 0,
                                                         'SHR': 0,
                                                         'OR': 0,
                                                         'JB': 0,
                                                         'DEC': 0,
                                                         'DECL': 0,
                                                         'INCL': 0,
                                                         'FXCH': 0,
                                                         'JP': 0,
                                                         'FSTP': 0,
                                                         'NOT': 0,
                                                         'PUSHF': 0,
                                                         'XCHG': 0,
                                                         'ADC': 0,
                                                         'CLC': 0,
                                                         'LCALL': 0,
                                                         'AAA': 0,
                                                         'FIADDL': 0,
                                                         'OUTSL': 0,
                                                         'XLAT': 0,
                                                         'ROLL': 0,
                                                         'LES': 0,
                                                         'OUTSB': 0,
                                                         'AAM': 0,
                                                         'DAS': 0,
                                                         'CLD': 0,
                                                         'NOTB': 0,
                                                         'IRET': 0,
                                                         'FSTPS': 0,
                                                         'SS': 0,
                                                         'CMC': 0,
                                                         'RORB': 0,
                                                         'FNSAVE': 0,
                                                         'FLDS': 0,
                                                         'FIADD': 0,
                                                         'JNO': 0,
                                                         'INCB': 0,
                                                         'CMPW': 0,
                                                         'ABCL': 0,
                                                         'MOVSWL': 0,
                                                         'SHRL': 0,
                                                         'CPUID': 0,
                                                         'FIMUL': 0,
                                                         'RORL': 0,
                                                         'SAL': 0,
                                                         'FNCLEX': 0,
                                                         'SETG': 0,
                                                         'FSUBL': 0,
                                                         'FCMOVU': 0,
                                                         'PSUBB': 0,
                                                         'DIVB': 0,
                                                         'RCRL': 0,
                                                         'MOVQ': 0,
                                                         'RDTSC': 0,
                                                         'RDPMC': 0,
                                                         'PCMPEQB': 0,
                                                         'FBLD': 0,
                                                         'FCMOVB': 0,
                                                         'FUCOMI': 0,
                                                         'FLDLG2': 0,
                                                         'FABS': 0,
                                                         'FCHS': 0,
                                                         'PREFETCHNTA': 0,
                                                         'XGETBV': 0,
                                                         'PI2FW': 0,
                                                         'FSTSW': 0,
                                                         'ADDPD': 0,
                                                         'DIVSD': 0,
                                                         'PALIGNR': 0,
                                                         'GETSEC': 0
                                                         }


        pe = pefile.PE(sample_path)

        for section in pe.sections:
            flags = []

            for flag in sorted(section_flags):
                if getattr(section, flag[0]):
                    flags.append(flag[0])
            if 'IMAGE_SCN_MEM_EXECUTE' in flags:
                iterable = distorm3.DecodeGenerator(0, section.get_data(), distorm3.Decode32Bits)

                for (offset, size, instruction, hexdump) in iterable:
                    op_code = instruction.split(" ")[0]
                    if op_code in result_opcoded_count_dict.keys():
                        result_opcoded_count_dict[op_code] += 1

                for flag in sorted(section_flags):
                    if getattr(section, flag[0]):
                        flags.append(flag[0])

        pe.parse_data_directories()

        op_list_count =list(result_opcoded_count_dict.values())

        return op_list_count


def distorms_ml_jobs_save():
    file_path = "D:\\Allinone\\Programing\\Python\\악성코드통합\\R&D_데이터_챌린지_2018\\TestSet\\"
    file_full_path_list = [os.path.join(file_path, sample) for sample in os.listdir(file_path)]
    file_predict_path="./preditc_distorm_file.json"
    result_dict={}
    for sample_full_path in file_full_path_list:
        op_list_count=opcode_info_get(sample_full_path)
        result_dict[os.path.basename(sample_full_path)]=op_list_count


    with open(file_predict_path, 'w', encoding='utf-8') as make_file:
        json.dump(result_dict, make_file)


def distorms(save_file_path):
    with open(save_file_path, 'r') as distorm_file_handle:
        distorm_dics = {}
        while True:
            lines = distorm_file_handle.readline()
            if not lines: break
            split_list = lines.split('\t')
            distorm_dics[split_list[0]] = split_list [1:78]

    return distorm_dics


def size_label(FILENAME):
    file_size_result=[0 for i in range(1)]
    file_size=os.path.getsize(FILENAME)/1024
    if file_size<100:
        file_size_result[0]=1
        return file_size_result
    elif 100<file_size<500:
        file_size_result[0]=2
        return file_size_result
    elif 500<file_size<800:
        file_size_result[0]=3
        return file_size_result
    elif 800<file_size<1400:
        file_size_result[0]=4
        return file_size_result
    elif 1400<file_size<2000:
        file_size_result[0]=5
        return file_size_result
    elif 2000<file_size<2500:
        file_size_result[0]=6
        return file_size_result
    elif 2500<file_size<3500:
        file_size_result[0]=7
        return file_size_result
    elif 3500<file_size<4000:
        file_size_result[0]=8
        return file_size_result
    elif 4000<file_size:
        file_size_result[0]=9
        return file_size_result

mutex_file.close()
mutex_file2.close()
mutex_file3.close()