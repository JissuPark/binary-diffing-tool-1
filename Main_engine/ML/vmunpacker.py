import time
import time, ctypes

import win32gui

import pywintypes
import sys
import os
import commctrl
import ctypes
from win32con import PAGE_READWRITE, MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, PROCESS_ALL_ACCESS
import win32gui
import win32api
import sys
import time
import win32con
import win32api, win32con, win32gui, win32ui, win32service, os, time

import pefile
from multiprocessing import Process, current_process ,Queue, Pool
import threading
import shutil
import subprocess


GetWindowThreadProcessId = ctypes.windll.user32.GetWindowThreadProcessId
VirtualAllocEx = ctypes.windll.kernel32.VirtualAllocEx
VirtualFreeEx = ctypes.windll.kernel32.VirtualFreeEx
OpenProcess = ctypes.windll.kernel32.OpenProcess
WriteProcessMemory = ctypes.windll.kernel32.WriteProcessMemory
ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory

################################################
def Mal_packer():
    folder_path = "D:\\Allinone\\Programing\\Python\\악성코드통합\\R&D_데이터_챌린지_2019"
    save_path = "D:\\Allinone\\Programing\\Python\\project\\r_d_challenge\ML\\Mal_packer"

    with open('D:\\Allinone\\Programing\\Python\\project\\r_d_challenge\\classify\\Mal_packer.csv') as csv_file_handle:
        while True:
            data = csv_file_handle.readline()
            if not data: break

            split_data = data.split(',')
            file_base_name = split_data[0]
            file_name = os.path.join(folder_path, file_base_name)

            if os.path.isfile(file_name) == False:
                continue
            file_save_path = os.path.join(save_path, file_base_name)
            shutil.move(file_name, file_save_path)


################################################

def Anti_mal_script():
    folder_path="D:\\Allinone\\Programing\\Python\\악성코드통합\\R&D_데이터_챌린지_2019"
    save_path="D:\\Allinone\\Programing\\Python\\project\\r_d_challenge\ML\\Anti_mal_script"

    with open('D:\\Allinone\\Programing\\Python\\project\\r_d_challenge\\classify\\Anti_Script_PE.csv', encoding='utf-8') as csv_file_handle:
        while True:
            data = csv_file_handle.readline()
            if not data: break

            split_data = data.split(',')
            file_base_name = split_data[0]
            file_name = os.path.join(folder_path, file_base_name)

            if os.path.isfile(file_name)==False:
                continue
            file_save_path=os.path.join(save_path,file_base_name)
            shutil.move(file_name, file_save_path)

################################################
def packer_shutil():
    folder_path="D:\\Allinone\\Programing\\Python\\악성코드통합\\R&D_데이터_챌린지_2019"
    save_path="D:\\Allinone\\Programing\\Python\\project\\r_d_challenge\ML\\upx_aspack_fsg"
    save_path2="D:\\Allinone\\Programing\\Python\\project\\r_d_challenge\ML\\vmunpacker_list"

    with open('D:\\Allinone\\Programing\\Python\\project\\r_d_challenge\\classify\\2019_output1_final.csv') as csv_file_handle:
        while True:
            data = csv_file_handle.readline()
            if not data: break

            split_data = data.split(',')
            file_base_name = split_data[1]
            file_name = os.path.join(folder_path, file_base_name)

            file_save_path=os.path.join(save_path,file_base_name)
            if os.path.isfile(file_name)==False:
                continue

            packer_type =  ' '.join(split_data[2:])
            if 'aspack' in packer_type.lower():
                shutil.move(file_name,file_save_path)
                continue
            if 'upx' in packer_type.lower():
                shutil.move(file_name, file_save_path)
                continue
            if 'fsg' in packer_type.lower():
                shutil.move(file_name, file_save_path)
                continue
            for packers in packer_list:
                if packers in packer_type.lower():
                    file_save_path = os.path.join(save_path2, file_base_name)
                    shutil.move(file_name, file_save_path)
                    continue

################################################


################################################
packer_list=['beroexepacker', 'pecompact','vgcrypt', 'nspack', 'expressor', 'npack', 'dxpack', 'epack', 'bjfnt', 'mew5', 'mew', 'packman', 'pediminisher', 'pex', 'petite', 'winkript', 'pklite32pepack', 'pcshrinker', 'wwpack32', 'upack', 'rlpack', 'exe32pack', 'kbys', 'yoda', 'xj', 'exestealth', 'hidepe', 'jdpack', 'jdprotect', 'pencrypt', 'stone', 'telock', 'ezip', 'hmimys', 'lamecrypt', 'depack', 'polyene', 'dragonarmour', 'ep protector', 'packitbitch', 'trojan_protect', 'anti007', 'mkfpack', 'yzpackspack', 'naked', 'upolyx', 'stealthpe', 'mslrh', 'morphine', 'rlpack', 'exefog', 'asdpack', 'pebundle', 'neolite']


def queue_sample():
    queue1=Queue()
    queue2=Queue()
    folder_path="D:\\Allinone\\Programing\\Python\\project\\r_d_challenge\\ML\\vmunpacker_list\\"
    with open('D:\\Allinone\\Programing\\Python\\project\\r_d_challenge\\classify\\2019_output1_final.csv') as csv_file_handle:
        while True:
            data = csv_file_handle.readline()
            if not data: break

            split_data = data.split(',')
            file_name = os.path.join(folder_path, split_data[1])
            if os.path.isfile(file_name)==False:
                continue

            packer_type =  ' '.join(split_data[2:])
            if 'aspack' in packer_type.lower():
                queue1.put((file_name, 1))
                continue
            if 'upx' in packer_type.lower():
                queue1.put((file_name, 2))
                continue
            if 'fsg' in packer_type.lower():
                queue1.put((file_name, 3))
                continue
            for packers in packer_list:
                if packers in packer_type.lower():
                    queue2.put(file_name)
                    continue

    return queue1, queue2
################################################

def sub_unpacker(sample_path,flags):
    if flags==1:
        process_flag = subprocess.Popen(["MNM_Unpacker.exe", "a", sample_path], shell=True).wait()
        time.sleep(2)
        if process_flag == 1:
            print("Process Not Run")


    elif flags==2:
        print(sample_path)
        process_flag = subprocess.Popen(["upx.exe", "-d", sample_path], shell=True).wait()
        time.sleep(2)
        if process_flag == 1:
            process_flag2=subprocess.Popen(["upx2.exe", "-d", sample_path], shell=True).wait()
            if process_flag2 == 1:
                subprocess.Popen(["upx3.exe", "-d", sample_path], shell=True).wait()


    elif flags==3:
        process_flag = subprocess.Popen(["MNM_Unpacker.exe", "f", sample_path], shell=True).wait()
        if process_flag == 1:
            print("Process Not Run")

        time.sleep(2)



################################################

def make_pycwnd(hwnd):
    PyCWnd = win32ui.CreateWindowFromHandle(hwnd)
    return PyCWnd

child_hwnd={}
def window_function(hwnd,lparm):
    s=win32gui.GetWindowText(hwnd)
    wnd_text = win32gui.GetClassName(hwnd)
    #print("[child_hwnd]: {}\t[txt] {}\t[class] : {}".format(hex(hwnd).upper(),str(s),wnd_text))
    child_hwnd[str(s)]=(hwnd,wnd_text)
    return 1




def send_input_hax(hwnd, msg):
    for c in msg:
        if c == "\n":
            win32api.SendMessage(hwnd, win32con.WM_KEYDOWN, win32con.VK_RETURN, 0)
            win32api.SendMessage(hwnd, win32con.WM_KEYUP, win32con.VK_RETURN, 0)
        else:
            win32api.SendMessage(hwnd, win32con.WM_CHAR, ord(c), 0)
    return None


def click_MouseLbtn(hWnd):
    (left, top, right, bottom) = win32gui.GetWindowRect(hWnd)
    win32api.SetCursorPos((right-2,top+2))
    time.sleep(0.05)
    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, 0, 0)
    time.sleep(0.05)
    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, 0, 0)
    return True


def winfun(hwnd, lparam):
    s = win32gui.GetWindowText(hwnd)
    if len(s) > 3:
        print("winfun, child_hwnd: %d   txt: %s" % (hwnd, s))
    return 1


# main 입니다.
def vmunpacker(Path):
    print(Path)

    while True:
        try:
            main_app="VMUnpacker V1.3 Public Version"
            hwnd=win32gui.FindWindow(None,main_app)
            win32gui.SetForegroundWindow(hwnd)
           #'...' button
            button1 = win32gui.GetDlgItem(hwnd, 0x000003E8)

            #'unpack' button
            button2 = win32gui.GetDlgItem(hwnd, 0x000003E9)

            #'파일 name'
            File_paths = win32gui.GetDlgItem(hwnd, 0x000003EC)

            click_MouseLbtn(button1)
            time.sleep(1)

            main_app2="열기"
            hwnd2=win32gui.FindWindow(None,main_app2)
            #win32api.SendMessage


            #FilePath2
            File_paths2 = win32gui.GetDlgItem(hwnd2,0x0000047C)
            time.sleep(0.5)

            #'파일열기' button
            button3 = win32gui.GetDlgItem(hwnd2, 0x00000001)

            SendMessage = ctypes.windll.user32.SendMessageW

            SendMessage(File_paths2, 0xC, 0, Path)
            time.sleep(0.5)
            #win32gui.EnumChildWindows(hwnd, winfun, None)

            click_MouseLbtn(button3)
            click_MouseLbtn(button2)
            time.sleep(10)
            return
        except:
            time.sleep(5)
            continue




def main_1(queue1):
    while queue1.empty() != True:

        get_tuple = queue1.get()
        sample_path = get_tuple[0]
        flags = get_tuple[1]

        if flags == 1:
            print("FSG")
            sub_unpacker(sample_path, 1)
            # os.remove(sample_path)
            continue

        elif flags == 2:
            print("UPX")
            sub_unpacker(sample_path, 2)
            # os.remove(sample_path)
            continue
        elif flags == 3:
            print("ASPACK")
            sub_unpacker(sample_path, 3)
            # os.remove(sample_path)
            continue

    return


def main_2(queue2):
    while queue2.empty() != True:
        file_name= queue2.get()
        vmunpacker(file_name)



def name_replace():
    folder_path="D:\\Allinone\\Programing\\Python\\project\\r_d_challenge\\ML\\vmunpacker_list\\"
    unpack_sample_full_path_list=[os.path.join(folder_path,sample) for sample in os.listdir(folder_path)]
    for unpack_sample in unpack_sample_full_path_list:
        unpack_sample_basename=os.path.basename(unpack_sample)
        dir_name=os.path.dirname(unpack_sample)

        if 'unpack' in unpack_sample_basename:
            sample_full_path=os.path.join(dir_name,unpack_sample_basename.split('_')[0]+".vir")
            try:
                os.remove(sample_full_path)
            except:pass
            os.rename(sample_full_path, unpack_sample)

        elif '_' ==unpack_sample_basename[-1:]:
            sample_full_path=os.path.join(dir_name,unpack_sample_basename[:-1])
            try:
                os.remove(sample_full_path)
            except:pass
            os.rename(sample_full_path, unpack_sample)


if __name__ == '__main__':
    Mal_packer()
    #name_replace()
    #Anti_mal_script()
    #packer_shutil()
    #queue1,queue2=queue_sample()
    #main_1(queue1)
    #main_2(queue2)
'''
    proc_list =[]
    for _ in range(0 ,5):
        proc =Process(target=main_1,args=(queue1,))
        proc_list.append(proc)
    for proc in proc_list:
        proc.start()
    main_2(queue2)
    for proc in proc_list:
        proc.join()
'''
