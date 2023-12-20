from .error import WRError
from .protocol import WRProtocol
import xml.etree.ElementTree as ET
import re, time

class WmiInstance:
    _data=None
    def __init__(self, xml_str="", xml_root=None, xml_schema=None):
        if xml_str is not None and len(xml_str) > 0:
            self._xml_str=xml_str
            self._root = ET.fromstring(xml_str)
        elif xml_root is not None:
            self._root = xml_root
        else:
            raise TypeError("xml_str or xml_root must be defined")
        if '}' not in self._root.tag:
            raise TypeError("Bad XML data.")
        temp=self._root.tag.split('}')
        self.class_name=temp[1]
        self._xmlns = { "p": temp[0][1:]}
        self._xml_schema=xml_schema
    def keys(self):
        properties=[]
        for p in self._root:
            if '}' in p.tag:
                properties += [p.tag.split('}')[1]]
            else:
                properties += [p.tag]
        return properties
    def data(self, update=False):
        if isinstance(self._data, dict) and not update: return self._data
        self._data = {}
        for p in self._xml_schema:
            if p.tag[:8] != "PROPERTY": continue
            self._data[p.attrib['NAME']] = self.__getattr__(p.attrib['NAME'])
        return self._data
    def __repr__(self):
        return "<%s class_name=%s with_schema=%s data=%s>" % (
            self.__class__.__name__, 
            self.class_name, 
            self._xml_schema is not None,
            str(self.data()))
    def __str__(self):
        return str(self.data())
    def __contains__(self, key):
        return self._root.find("./p:%s" % key, self._xmlns) is not None
    def __getitem__(self, key):
        return self.__getattr__(key)
    def get(self, key, default=None):
        try:
            return self.__getattr__(key)
        except AttributeError:
            return default
    def return_type(self, xml_value, value_type):
        if value_type[1:4] == "int":
            return int(xml_value.text)
        elif value_type[:4] == "real":
            return float(xml_value.text)
        elif value_type == "boolean":
            return True if xml_value.text.lower() == "true" else False
        elif value_type == "datetime":
            xml_value=xml_value.find("./{http://schemas.dmtf.org/wbem/wscim/1/common}Datetime", self._xmlns)
            dt_str=xml_value.text
            if dt_str[-1] == "Z":
                timezonesecs=0
            else:
                timezone=dt_str[-6:]
                timezonesecs=(int(timezone[-2:])+int(timezone[1:3])*60) * (-1 if timezone[0] == '+' else 1) *60
            lbt=time.strptime(dt_str[:19], "%Y-%m-%dT%H:%M:%S")
            return time.mktime(lbt)+timezonesecs
        elif value_type == "string":
            return xml_value.text
        else:
            raise TypeError("Invalid type %s for %s" % (value_type, attr))

    def __getattr__(self, attr):
        ''' Gets the attribute from the WMI Instance '''
        value=self._root.findall("./p:%s" % attr, self._xmlns)
        array=False
        if len(value) == 0:
            return None
        nil=value[0].attrib.get('{http://www.w3.org/2001/XMLSchema-instance}nil', 'false')
        if nil == 'true':
            return None
        value_type="string"
        if self._xml_schema is not None:
            vt_xml=self._xml_schema.find(".//*[@NAME='%s']" % attr)
            if vt_xml is None:
                raise AttributeError(attr)
            value_type=vt_xml.attrib["TYPE"]
            if vt_xml.tag == "PROPERTY.ARRAY":
                array = True
            else:
                array = False
            if not array:
                return self.return_type(value[0], value_type)
            else:
                arrvalue=[]
                for item in value:
                    arrvalue += [self.return_type(item, value_type)]
                return arrvalue

class WMIQuery():
    base_uri='http://schemas.microsoft.com/wbem/wsman/1/wmi'
    schema_uri='http://schemas.dmtf.org/wbem/cim-xml/2/cim-schema/2/*'
    _xml_schema=None
    _wql=None
    class_name=None
    resource_uri=""
    _ec=None

    def __init__(self, class_name=None, namespace="root/cimv2", wql=None, protocol=None, max_elements=50, *args, **kwargs):
        if protocol is not None:
            if not isinstance(protocol, WRProtocol):
                raise Exception("Can only accept WRProtocol")
            self.p = protocol
        else:
            self.p = WRProtocol(*args, **kwargs)
        if isinstance(wql, str):
            self._wql = wql
            temp = re.search(r'FROM (\S+)', wql, re.IGNORECASE)
            if temp is None:
                raise ValueError("Invalid WQL query.")
            self.class_name = temp[1]
        elif isinstance(class_name, str):
            self.class_name = class_name
        else:
            raise ValueError("one parameter 'class_name' or 'wql' must be defined.")
        self.namespace = namespace
        self.max_elements = max_elements

    def get_schema_xml(self):
        if self._xml_schema is not None and self._xml_schema.attrib['NAME'] == self.class_name:
            return
        self._schema_str = self.p.get(self.schema_uri, selector=[{
                '@Name': '__cimnamespace', 
                '#text': self.namespace
            },
            {
                '@Name': 'ClassName',
                '#text': self.class_name
            }])
        self._schema_root=ET.fromstring(self._schema_str)
        self._xml_schema=self._schema_root.find(".//CLASS")

    def __iter__(self):
        self.resource_uri = "%s/%s/" % (self.base_uri, self.namespace)
        if self._wql is not None:
            self.resource_uri += "*"
        else:
            self.resource_uri += self.class_name
        self.get_schema_xml()
        self._xml_enum = ET.fromstring(self.p.enumerate(self.resource_uri, wql=self._wql))
        self._ec = self._xml_enum.find('s:Body/wsen:EnumerateResponse/wsen:EnumerationContext', 
            self.p.xmlns).text
        self._item_iter = iter([])
        return self

    def __next__(self):
        while True:
            try:
                next_item = next(self._item_iter)
                break
            except StopIteration:
                if self._ec is None:
                    raise
                self._xml_pull = ET.fromstring(self.p.pull(self.resource_uri, self._ec, max_elements=self.max_elements))
                items = self._xml_pull.findall('.//wsen:Items/', self.p.xmlns)
                self._item_iter = iter(items)
                if self._xml_pull.find('s:Body/wsen:PullResponse/wsen:EndOfSequence', self.p.xmlns) is not None:
                    self._ec = None
                else:
                    self._ec = self._xml_pull.find('s:Body/wsen:PullResponse/wsen:EnumerationContext',
                        self.p.xmlns).text
        return WmiInstance(xml_root=next_item, xml_schema=self._xml_schema)

    def release(self):
        if self._ec is not None:
            self.p.release(self.resource_uri, self._ec)
            return True
        return False

    def get_instance(self, class_name):
        try:
            self._class_data = self.p.get("%s/%s/%s" % (self.base_uri, self.namespace, class_name))
        except WRError as e:
            error_code = e.fault_detail.find('wmie:MSFT_WmiError/wmie:error_Code', 
                self.p.xmlns)
            if error_code is not None and error_code.text == '2150859002':
                return self.enumerate_instance(class_name)
            return e
        except Exception as e:
            return e

        self._root = ET.fromstring(self._class_data)
        xmldata=self._root.find('.//p:%s' % class_name, {'p': "%s/%s/%s" % (self.base_uri, self.namespace, class_name)})
        data = self.wmixmltodict(xmldata, class_name)
        return data

    def wql(self, wql):
        return self.enumerate_instance('*', wql=wql)

    def enumerate_instance(self, class_name, en_filter=None, wql=None, download_schema=True):
        self.resource_uri = "%s/%s/%s" % (self.base_uri, self.namespace, class_name)
        self._class_data = self.p.enumerate(self.resource_uri, en_filter=en_filter, wql=wql)
        if wql is not None:
            self.class_name = re.search(r'FROM (\S+)', wql)[1]
        else:
            self.class_name = class_name

        self._root = ET.fromstring(self._class_data)
        self._ec = self._root.find('s:Body/wsen:EnumerateResponse/wsen:EnumerationContext', 
            self.p.xmlns).text

        data = []
        self.get_schema_xml()
        while True:
            self.ec_data = self.p.pull(self.resource_uri, self._ec)
            self._pullresponse = ET.fromstring(self.ec_data)

            items = self._pullresponse.findall('.//wsen:Items/', 
                self.p.xmlns)
            for item in items:
                data += [WmiInstance(xml_root=item, xml_schema=self._xml_schema)]

            if self._pullresponse.find('s:Body/wsen:PullResponse/wsen:EndOfSequence', 
                self.p.xmlns) is not None:
                break
            _ec = self._pullresponse.find('s:Body/wsen:PullResponse/wsen:EnumerationContext', 
                self.p.xmlns)
            if _ec is None:
                raise WRError("Invalid EnumerationContext.")
            self._ec = _ec.text
        return data


    def wmixmltodict(self, data_root, class_name):
        data = {}
        nil = "{%s}nil" % self.p.xmlns['xsi']
        for i in data_root.findall('./'):
            tagname = i.tag.split('}')
            if len(tagname) > 1:
                tagname = tagname[1]
            else:
                tagname = tagname[0]
            if i.attrib.get(nil, 'false') == 'true':
                data[tagname] = None
            else:
                if i.text is not None:
                    data[tagname] = i.text
                else:
                    data[tagname]={}
                    for e in i.findall('./'):
                        # TODO: improve this to remove namespace
                        e_tagname=e.tag.split('}')
                        if len(e_tagname) > 1:
                            e_tagname = e_tagname[1]
                        else:
                            e_tagname = e_tagname[0]

                        data[tagname][e_tagname] = e.text
        return data

#class WMICommand(WinRMCommand):
#    def __init__(self, shell, class_name=None, class_filter=None):
#        WinRMCommand.__init__(self, shell)
#        self.class_name = class_name
#        self.class_filter = class_filter
#        self.interactive = self.class_name is not None
#
#    def run(self):
#        params = []
#        self.error = False
#        if self.class_name is not None:
#            params += [ 'PATH', self.class_name ]
#            if self.class_filter is not None:
#                params += [ 'WHERE', self.class_filter ]
#            params += [ 'GET', '/FORMAT:RAWXML' ]
#        self.command_id = self.shell.run_command('wmic', params)
#        self.receive()
#        if self.class_name is not None:
#            self.process_result()
#
#    def process_result(self):
#        try:
#            self.root = ET.fromstringlist(self.std_out.replace('\r','').split('\n')[:-1])
#        except Exception as e:
#            return
#        for property in self.root.findall(".//PROPERTY"):
#            n=property.attrib['NAME']
#            v=property.find("./VALUE")
#            self.data[n]=v.text if v is not None else None
#
#    def __repr__(self):
#        return "<%s interactive=%s code=%d%s%s error=%s std_out_bytes=%d std_err_bytes=%d>" % \
#            (self.__class__.__name__, self.interactive, self.code,
#                " class_name=%s" % self.class_name if self.class_name is not None else "",
#                " class_filter=%s" % self.class_filter if self.class_filter is not None else "",
#                self.error,
#                len(self.std_out), len(self.std_err))
#
