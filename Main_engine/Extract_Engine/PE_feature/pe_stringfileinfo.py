import win32api

def getFileProperties(fname):

    propNames = ('LegalCopyright', 'ProductName',  'OriginalFilename', 'InternalName',
                 'ProductVersion', 'FileDescription', 'FileVersion', 'Comments')

    props = {'StringFileInfo': None, 'FileVersion': None}

    try:
        fixedInfo = win32api.GetFileVersionInfo(fname, '\\')
        props['FileVersion'] = "%d.%d.%d.%d" % (fixedInfo['FileVersionMS'] / 65536,
                fixedInfo['FileVersionMS'] % 65536, fixedInfo['FileVersionLS'] / 65536,
                fixedInfo['FileVersionLS'] % 65536)

        lang, codepage = win32api.GetFileVersionInfo(fname, '\\VarFileInfo\\Translation')[0]

        strInfo = {}
        for propName in propNames:
            strInfoPath = u'\\StringFileInfo\\%04X%04X\\%s' % (lang, codepage, propName)
            ## print str_info
            strInfo[propName] = win32api.GetFileVersionInfo(fname, strInfoPath)
            #print(strInfo[propName])
            # if propName == 'FileDescription':
            #     strInfo[propName] = propNames[propName]
            # else:
            #     continue

        props['StringFileInfo'] = strInfo
        props['StringFileInfo']['FileVersion'] = props['FileVersion']
    except:
        pass
    return props