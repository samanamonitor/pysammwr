from .protocol import WRProtocol
import xml.etree.ElementTree as ET
import struct

hkeynames = {
    0x80000000: 'HKEY_CLASSES_ROOT',
    0x80000001: 'HKEY_CURRENT_USER',
    0x80000002: 'HKEY_LOCAL_MACHINE',
    0x80000003: 'HKEY_USERS',
    0x80000005: 'HKEY_CURRENT_CONFIG',
    0x80000006: 'HKEY_DYN_DATA'
}
HKEY_CLASSES_ROOT = 0x80000000
HKCR = HKEY_CLASSES_ROOT
HKEY_CURRENT_USER = 0x80000001
HKCU = HKEY_CURRENT_USER
HKEY_LOCAL_MACHINE = 0x80000002
HKLM = HKEY_LOCAL_MACHINE
HKEY_USERS = 0x80000003
HKU = HKEY_USERS
HKEY_CURRENT_CONFIG = 0x80000005
HKEY_DYN_DATA = 0x80000006

REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_MULTI_SZ = 7
REG_QWORD = 11

class CIM_Registry:
    typemethods = {
        'REG_SZ':        'GetStringValue',
        'REG_EXPAND_SZ': 'GetExpandedStringValue',
        'REG_BINARY':    'GetBinaryValue',
        'REG_DWORD':     'GetDWORDValue',
        'REG_MULTI_SZ':  'GetMultiStringValue',
        'REG_QWORD':     'GetQWORDValue'
    }
    typenames = {
        1: 'REG_SZ',
        2: 'REG_EXPAND_SZ',
        3: 'REG_BINARY',
        4: 'REG_DWORD',
        7: 'REG_MULTI_SZ',
        11: 'REG_QWORD'
    }


    def __init__(self, protocol=None, *args, **kwargs):
        if protocol is not None:
            if not isinstance(protocol, WRProtocol):
                raise Exception("Can only accept WRProtocol")
            self.p = protocol
        else:
            self.p = WRProtocol(*args, **kwargs)
        self.resource_uri = "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/StdRegProv"
        self.cimnamespace = "root/cimv2"
        self.namespaces = {
            'p': self.resource_uri
        }
        self._path = ''

    def reviewreturnvalue(self):
        result = int(self._root.find('.//p:ReturnValue', namespaces=self.namespaces).text)
        if result == 2:
            raise FileNotFoundError(self._path)
        elif result == 1:
            raise Exception("ERROR_INVALID_FUNCTION - %s" % (self._path))
        elif result == 2147749893:
            raise TypeError("%s" % (self._path))
        elif result == 0:
            pass
        else:
            raise TypeError("Retrieval error %d at %s" % (result, self._path))


    def enumkey(self, hDefKey, sSubKeyName):
        self._path = "%s\\%s" % (hkeynames[hDefKey], sSubKeyName)
        res = self.p.execute_method(self.cimnamespace, self.resource_uri, 'EnumKey', hDefKey=hDefKey, sSubKeyName=sSubKeyName)
        self._root = ET.fromstring(res)
        self.reviewreturnvalue()
        snames = self._root.findall('.//p:sNames', namespaces=self.namespaces)
        return [ i.text for i in snames ]

    def enumvalues(self, hDefKey, sSubKeyName):
        self._path = "%s\\%s" % (hkeynames[hDefKey], sSubKeyName)
        res = self.p.execute_method(self.cimnamespace, self.resource_uri, 'EnumValues', hDefKey=hDefKey, sSubKeyName=sSubKeyName)
        self._root = ET.fromstring(res)
        self._hDefKey = hDefKey
        self._sSubKeyName = sSubKeyName
        self.reviewreturnvalue()
        snames = self._root.findall('.//p:sNames', namespaces=self.namespaces)
        types = self._root.findall('.//p:Types', namespaces=self.namespaces)
        return list(map(lambda x, y: (x.text, self.typenames[int(y.text)]), snames, types))

    def getvalue(self, hDefKey, sSubKeyName, sValueName, valueType):
        self._path = "%s\\%s\\%s" % (hkeynames[hDefKey], sSubKeyName, sValueName)
        self._method = self.typemethods.get(valueType, None)
        if self._method is None:
            raise TypeError("Invalid type %s" % valueType)
        self._kwargs = {
            'hDefKey': hDefKey, 
            'sSubKeyName': sSubKeyName, 
            'sValueName':sValueName
        }
        res = self.p.execute_method(self.cimnamespace, self.resource_uri, self._method, **self._kwargs)
        self._root = ET.fromstring(res)
        self.reviewreturnvalue()
        func = self.__getattribute__(self._method)
        return func()


    def GetDWORDValue(self):
        uvalue = self._root.find('.//p:uValue', namespaces=self.namespaces).text
        return int(uvalue)

    def GetQWORDValue(self):
        uvalue = self._root.find('.//p:uValue', namespaces=self.namespaces).text
        return int(uvalue)

    def GetStringValue(self):
        svalue = self._root.find('.//p:sValue', namespaces=self.namespaces).text
        return svalue

    def GetMultiStringValue(self):
        svalues = self._root.findall('.//p:sValue', namespaces=self.namespaces)
        return list(map(lambda x: x.text, svalues))

    def GetExpandedStringValue(self):
        svalue = self._root.find('.//p:sValue', namespaces=self.namespaces).text
        return svalue

    def GetBinaryValue(self):
        uvalues = self._root.findall('.//p:uValue', namespaces=self.namespaces)
        uvalues = list(map(lambda x: int(x.text), uvalues))
        return struct.pack(len(uvalues)*'B', *uvalues)


class CIM_RegistryValue(CIM_Registry):
    def __init__(self, hDefKey, sSubKeyName, sValueName, valueType, protocol=None, *args, **kwargs):
        super(CIM_RegistryValue, self).__init__(protocol=protocol, *args, **kwargs)
        self._hDefKey = hDefKey
        self.sSubKeyName = sSubKeyName
        self.sValueName = sValueName
        self.valueType = valueType
        self._path = "%s\\%s\\%s" % (hkeynames[self._hDefKey], sSubKeyName, sValueName)

    def __repr__(self):
        return "<%s %s(%s)>" % (self.__class__.__name__, self._path, self.valueType)

    @property
    def value(self):
        return self.getvalue(self._hDefKey, self.sSubKeyName, self.sValueName, self.valueType)

class CIM_RegistryKey(CIM_Registry):
    def __init__(self, hDefKey, sSubKeyName, protocol=None, *args, **kwargs):
        super(CIM_RegistryKey, self).__init__(protocol=protocol, *args, **kwargs)
        self._hDefKey = hDefKey
        self._sSubKeyName = sSubKeyName
        self._path = "%s\\%s" % (hkeynames[self._hDefKey], sSubKeyName)
        self._subkeys = None
        self._values = None

    def nav(self, sSubKeyName):
        if self._subkeys is None:
            self._subkeys = self.enumkey(self._hDefKey, self._sSubKeyName)
        if sSubKeyName not in self._subkeys:
            raise KeyError("Key %s doesn't exist." % sSubKeyName)
        newbasepath = self._sSubKeyName + "\\" if len(self._sSubKeyName) > 0 else self._sSubKeyName
        return CIM_RegistryKey(self._hDefKey, newbasepath + sSubKeyName, protocol=self.p)

    def getvalue(self, sValueName):
        if self._values is None:
            self._values = self.enumvalues(self._hDefKey, self._sSubKeyName)
        found_value = None
        for n, t in self._values:
            if n == sValueName:
                found_value = (n, t)
                break
        if found_value is None:
            raise ValueError("Value %s doesn't exist." % sValueName)
        return CIM_RegistryValue(self._hDefKey, self._sSubKeyName, found_value[0], found_value[1], protocol=self.p)

    @property
    def children(self):
        newbasepath = self._sSubKeyName + "\\" if len(self._sSubKeyName) > 0 else self._sSubKeyName
        return map(lambda x: CIM_RegistryKey(self._hDefKey, newbasepath + x, 
            protocol=self.p), self.enumkey(self._hDefKey, self._sSubKeyName))

    @property
    def values(self):
        return map(lambda x: CIM_RegistryValue(self._hDefKey, self._sSubKeyName, x[0], x[1],
            protocol=self.p), self.enumvalues(self._hDefKey, self._sSubKeyName))

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, self._path)




