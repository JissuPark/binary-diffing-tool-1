import os,re
import pefile
import array,math

#mutex_file = open('C:\\Users\\vm\\Desktop\\Breakers\\binary-diffing-tool\\Main_engine\\ML\\mutex_strings_lists.txt', 'r')
mutex_file = open("./mutex_strings_lists.txt", 'r')
mutex_list = [line[:-1] for line in mutex_file]

#mutex_file2 = open('C:\\Users\\vm\\Desktop\\Breakers\\binary-diffing-tool\\Main_engine\\ML\\win32api_alphabet.txt', 'r')
mutex_file2 = open('./win32api_alphabet.txt', 'r')
mutex_list2 = [line2[:-1] for line2 in mutex_file2]

mutex_file3 = open('./win32api_category.txt', 'r')
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

def exstrings(FILENAME,regex=None):

    result=list()

    importlists = []



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
                if len(ipaddress_re.findall(BINDATA_REGEX2.group(2)[:-1])) >= 1:
                    result.append(ipaddress_re.findall(BINDATA_REGEX2.group(2)[:-1]))
                    continue
                elif len(email_re.findall(BINDATA_REGEX2.group(2)[:-1])) >= 1:
                    result.append(email_re.findall(BINDATA_REGEX2.group(2)[:-1]))
                    continue
                elif len(url_re.findall(BINDATA_REGEX2.group(2)[:-1])) >= 1:
                    result.append(url_re.findall(BINDATA_REGEX2.group(2)[:-1]))
                    continue

                for find_string in find_string_list:
                    if find_string in  BINDATA_REGEX2.group(2)[:-1].lower():
                        result.append(BINDATA_REGEX2.group(2)[:-1].lower())

                for find_string in wmi_list:
                    if find_string in  BINDATA_REGEX2.group(2)[:-1].lower():
                        result.append(BINDATA_REGEX2.group(2)[:-1].lower())

                for find_string in Registry_list:
                    if find_string in  BINDATA_REGEX2.group(2)[:-1].lower():
                        result.append(BINDATA_REGEX2.group(2)[:-1].lower())

                for find_string in cmd_list:
                    if find_string in  BINDATA_REGEX2.group(2)[:-1].lower():
                        result.append(BINDATA_REGEX2.group(2)[:-1].lower())

                for find_string in powershell_list:
                    if find_string in  BINDATA_REGEX2.group(2)[:-1].lower():
                        result.append(BINDATA_REGEX2.group(2)[:-1].lower())


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
                if len(ipaddress_re.findall(BINDATA_REGEX2.group(2)[:-1])) >= 1:
                    result.append(ipaddress_re.findall(BINDATA_REGEX2.group(2)[:-1]))
                    continue
                elif len(email_re.findall(BINDATA_REGEX2.group(2)[:-1])) >= 1:
                    result.append(email_re.findall(BINDATA_REGEX2.group(2)[:-1]))
                    continue
                elif len(url_re.findall(BINDATA_REGEX2.group(2)[:-1])) >= 1:
                    result.append(url_re.findall(BINDATA_REGEX2.group(2)[:-1]))
                    continue

                for find_string in find_string_list:
                    if find_string in  BINDATA_REGEX2.group(2)[:-1].lower():
                        result.append(BINDATA_REGEX2.group(2)[:-1].lower())

                for find_string in wmi_list:
                    if find_string in  BINDATA_REGEX2.group(2)[:-1].lower():
                        result.append(BINDATA_REGEX2.group(2)[:-1].lower())

                for find_string in Registry_list:
                    if find_string in  BINDATA_REGEX2.group(2)[:-1].lower():
                        result.append(BINDATA_REGEX2.group(2)[:-1].lower())

                for find_string in cmd_list:
                    if find_string in  BINDATA_REGEX2.group(2)[:-1].lower():
                        result.append(BINDATA_REGEX2.group(2)[:-1].lower())

                for find_string in powershell_list:
                    if find_string in  BINDATA_REGEX2.group(2)[:-1].lower():
                        result.append(BINDATA_REGEX2.group(2)[:-1].lower())

    fp.close()

    return result,entropys


FILENAME=r'D:\Project\PL자료\malware\Bluenoroff\19743cb098a54529ad1e37dc5856ab0f3703606d49debcd85034e59c48dda363'
result,entropys=exstrings(FILENAME)

print(entropys)
print(result)