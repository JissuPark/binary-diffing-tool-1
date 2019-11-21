#-*- coding: utf-8 -*-
import math
import numpy as np
import json
import array
import pefile
import sys
import distorm3
from hashlib import sha1
from hashlib import sha256
from hashlib import sha512
from hashlib import md5
import re
import os
import csv
from multiprocessing import Process, current_process ,Queue, Pool


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


def get_info(sample_path):
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

        filename=os.path.basename(sample_path)
        op_list_count =list(result_opcoded_count_dict.values())

        print(filename)
        return filename,op_list_count


################################################################################


save_file_path="./distorm.csv"
mal_path= "D:\\Allinone\\Programing\\Python\\악성코드통합\\Data_All\\"



def queue_input_file_path(queue):
    for (path, dir, files) in os.walk(mal_path):
        for filename in files:
            file_full_path = os.path.join(path, filename)
            queue.put(file_full_path)


def write_csv_data(filename,op_list_count):
    with open(save_file_path, 'a', newline='',encoding='utf-8') as csv_file:
        #CSV Write DATA
        writer = csv.writer(csv_file, delimiter=',')
        data=[filename]+op_list_count
        writer.writerow(data)

queue2=Queue()
def create_data_set(queue):
    while queue.empty() != True:
        sample_path=queue.get()
        try:
            filename, op_list_count=get_info(sample_path)
            write_csv_data(filename,op_list_count)
        except:
            queue2.put(sample_path)
            continue


if __name__=="__main__":
    queue=Queue()
    queue_input_file_path(queue)

    proc_list = []
    for _ in range(0, 10):
        proc = Process(target=create_data_set, args=(queue,))
        proc_list.append(proc)
    for proc in proc_list:
        proc.start()
    for proc in proc_list:
        proc.join()

    with open("./not_pe_error_file.txt",'w') as not_pe_file_handle:
        while queue2.empty() != True:
            sample_path=queue2.get()
            not_pe_file_handle.write(sample_path+'\n')
