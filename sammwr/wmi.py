from .error import WRError
from .protocol import WRProtocol
import xml.etree.ElementTree as ET
import re, time
import xmltodict

schema_cache = {}

def get_schema_xml(protocol, namespace, class_name):
    global schema_cache
    key = "%s/%s" % (namespace, class_name)
    if key in schema_cache:
        return schema_cache[key]

    schema_uri='http://schemas.dmtf.org/wbem/cim-xml/2/cim-schema/2/*'
    schema_str = protocol.get(schema_uri, selector=[{
            '@Name': '__cimnamespace',
            '#text': namespace
        },
        {
            '@Name': 'ClassName',
            '#text': class_name
        }])
    schema_root=ET.fromstring(schema_str)
    schema_cache[key] = schema_root.find(".//CLASS")

    return schema_cache[key]


class WmiReference:
    def __init__(self, protocol, xml_root):
        self._root = xml_root
        self.protocol = protocol
        self._selectors_dict = {}

        resource_uri_node = self._root.find('.//{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}ResourceURI')
        if resource_uri_node is not None:
            self._resource_uri = resource_uri_node.text
        else:
            raise TypeError("Reference cannot be followed without ResourceURI. %s" % ET.tostring(self._root))
        self._class_name = self._resource_uri.rsplit('/', 1)[-1]

        selector_set_node = self._root.find('.//{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}SelectorSet')
        if selector_set_node is not None:
            selectorset = xmltodict.parse(ET.tostring(selector_set_node))
            self._selectors = selectorset.get('ns0:SelectorSet', {}).get('ns0:Selector')
            if isinstance(self._selectors, list):
                self._selectors_dict = { i.get('@Name', 'unknown'): i.get('#text') for i in self._selectors }
            elif isinstance(self._selectors, dict):
                self._selectors_dict[self._selectors.get('@Name', 'unknown')] = self._selectors.get('#text')

        else:
            raise TypeError("Reference cannot be followed without SelectorSet. %s" % ET.tostring(self._root))

    def follow(self):
        data = self.protocol.get(self._resource_uri, selector=self._selectors)
        data_xml = ET.fromstring(data)
        instance = data_xml.find(".//p:%s" % self._class_name, {'p':self._resource_uri})
        return WmiInstance(instance, self.protocol)

    def __repr__(self):
        return "<%s class_name=%s selectors=%s" % (
            self.__class__.__name__,
            self._class_name, self._selectors_dict)

class WmiInstance:
    _data=None
    ns_class_pattern=re.compile(r'{(http://schemas.microsoft.com/wbem/wsman/1/wmi/(.*)/(.*))}')

    def __init__(self, xml_root, protocol):
        self.protocol = protocol
        self._root = xml_root
        match = next(re.finditer(self.ns_class_pattern, self._root.tag))
        allgroups = match.groups()
        if len(allgroups) != 3:
            raise TypeError("Invalid XML namespace. %s" % ET.tostring(self._root))
        self._xmlns = { "p": allgroups[0] }
        self.namespace = allgroups[1]
        self.class_name = allgroups[2]
        self._xml_schema=get_schema_xml(self.protocol, self.namespace, self.class_name)

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
            reference = False
            array = False
            vt_xml=self._xml_schema.find(".//*[@NAME='%s']" % attr)
            if vt_xml is None:
                raise AttributeError(attr)
            if vt_xml.tag == "PROPERTY.REFERENCE":
                reference = True
            elif vt_xml.tag == "PROPERTY.ARRAY":
                array = True
            if reference:
                return WmiReference(self.protocol, value[0])
            value_type=vt_xml.attrib["TYPE"]
            if not array:
                return self.return_type(value[0], value_type)
            else:
                arrvalue=[]
                for item in value:
                    arrvalue += [self.return_type(item, value_type)]
                return arrvalue

class WMIQuery():
    base_uri='http://schemas.microsoft.com/wbem/wsman/1/wmi'
    _wql=None
    class_name=None
    resource_uri=""
    _ec=None

    def __init__(self, class_name=None, namespace="root/cimv2", wql=None, selector=None, protocol=None, max_elements=50, *args, **kwargs):
        if protocol is not None:
            if not isinstance(protocol, WRProtocol):
                raise Exception("Can only accept WRProtocol")
            self.p = protocol
        else:
            self.p = WRProtocol(*args, **kwargs)
        if isinstance(wql, str):
            self._wql = wql
        elif isinstance(class_name, str):
            self.class_name = class_name
            self.selector = selector
        else:
            raise ValueError("one parameter 'class_name' or 'wql' must be defined.")
        self.namespace = namespace
        self.max_elements = max_elements

    def __iter__(self):
        self.resource_uri = "%s/%s/" % (self.base_uri, self.namespace)
        if self._wql is not None:
            self.resource_uri += "*"
            self._xml_enum = ET.fromstring(self.p.enumerate(self.resource_uri, wql=self._wql))
        else:
            self.resource_uri += self.class_name
            self._xml_enum = ET.fromstring(self.p.enumerate(self.resource_uri, selector=self.selector))
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
        return WmiInstance(xml_root=next_item, protocol=self.p)

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
        while True:
            self.ec_data = self.p.pull(self.resource_uri, self._ec)
            self._pullresponse = ET.fromstring(self.ec_data)

            items = self._pullresponse.findall('.//wsen:Items/', 
                self.p.xmlns)
            for item in items:
                data += [WmiInstance(xml_root=item, protocol=self.p)]

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
