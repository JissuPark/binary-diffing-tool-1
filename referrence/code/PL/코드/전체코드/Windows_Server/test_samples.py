import requests
import subprocess 
import sys
from distorm3 import DecomposeGenerator, Decode32Bits, Decode64Bits, Decode16Bits
import os
import shutil
import time
import psutil
import hashlib
import paramiko
import pefile
import pe_analyzer
import signal
import json


def convert_idb(sample_file_path):
    dt = Decode32Bits
    ida_path = "C:\\Program Files\\IDA 7.0\\idat.exe"
    process=subprocess.Popen([ida_path,"-A","-B","-P+",sample_file_path],shell=True)
    time.sleep(2)
    return process

def remove_json_pefile(sample_full_path):

    os.remove(sample_full_path)
    sample_base_name=os.path.splitext(os.path.basename(sample_full_path))[0]

    for sample_files in os.listdir(sample_default_path):
        if '.' in sample_files:
            if sample_base_name in sample_files:
                if '.idb' in sample_files:
                    continue
                os.remove(os.path.join(sample_path,sample_files))

sample_path="C:\\temp\\pe_sample\\kimsuky"
for sample in os.listdir(sample_path):
    sample_file_path=os.path.join(sample_path,sample)
    convert_idb(sample_file_path)
