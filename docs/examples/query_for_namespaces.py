import xml.etree.ElementTree as ET
from sammwr.protocol import WRProtocol
from sammwr.wmi import WMIQuery
import os
import datetime

username=os.environ['WRUSERNAME']
password=os.environ['WRPASSWORD']
endpoint=os.environ['WRENDPOINT']
c=WRProtocol(username=username, password=password, endpoint=endpoint)


def get_enumeration_context(res):
	ns={'n': 'http://schemas.xmlsoap.org/ws/2004/09/enumeration'}
	root=ET.fromstring(res)
	if root.find('.//n:EndOfSequence', namespaces=ns) is not None:
		return None
	return root.find('.//n:EnumerationContext', namespaces=ns).text

def print_class(res):
	root=ET.fromstring(res)
	for i in root.findall('.//CLASS'):
		print(i.attrib['NAME'])


selector=[{"@Name": "__namespace", "#text": "Root"}]
enum=c.enumerate(resource_uri, selector=selector)

c=WRProtocol(endpoint=endpoint, username=username, password=password)
def get_namespaces(c, root="Root"):
	''' List all namespaces '''
	resource_uri="http://schemas.microsoft.com/wbem/wsman/1/wmi/%s/__Namespace" % root
	enum=c.enumerate(resource_uri)
	ec=get_enumeration_context(enum)
	r=None
	while ec is not None:
		pull=c.pull(resource_uri, ec)
		if r is None:
			r = ET.fromstring(pull)
			items = r.find(".//{http://schemas.xmlsoap.org/ws/2004/09/enumeration}Items")
		else:
			temp = ET.fromstring(pull)
			temp_items = temp.find(".//{http://schemas.xmlsoap.org/ws/2004/09/enumeration}Items")
			for i in temp_items:
				items.append(i)
		ec=get_enumeration_context(pull)
	return [ x.text for x in r.findall(".//{http://schemas.microsoft.com/wbem/wsman/1/wmi/root/__NAMESPACE}Name")]

# List all classes in a namespace
def get_classes(c, root="root"):
	ns = { "e": "http://schemas.xmlsoap.org/ws/2004/09/enumeration" }
	resource_uri="http://schemas.dmtf.org/wbem/cim-xml/2/cim-schema/2/*"
	enum=c.enumerate(resource_uri, selector=[{"@Name": "__cimnamespace", "#text": root}])
	ec=get_enumeration_context(enum)
	r=None
	while ec is not None:
		pull=c.pull(resource_uri, ec)
		if r is None:
			r = ET.fromstring(pull)
			items = r.find(".//e:Items", ns)
		else:
			temp = ET.fromstring(pull)
			temp_items = temp.find(".//e:Items", ns)
			for i in temp_items:
				items.append(i)
		ec=get_enumeration_context(pull)
	return [ x.attrib.get('NAME') for x in items ]

class CIMClient:
	resource_uri="http://schemas.dmtf.org/wbem/cim-xml/2/cim-schema/2/*"
	def __init__(self, protocol, namespace="root", selector=None):
		self.p = protocol
		self.namespace = namespace
		self.selector = selector
	@property
	def classes(self):
		return CIMClassIterator(self.p, self.resource_uri, self.selector)

class CIMClassIterator:
	namespaces={'n': 'http://schemas.xmlsoap.org/ws/2004/09/enumeration'}
	def __init__(self, protocol, resource_uri, namespace="root", max_elements=10, **kwargs):
		self.p = protocol
		self.resource_uri = resource_uri
		self.namespace = namespace
		self.max_elements = max_elements
		self.selector = kwargs.get("selector")
		self._enumerate()
	def __iter__(self):
		self._enumerate()
		return self
	def __next__(self):
		if self._data is None:
			self._pull()
		try:
			return next(self._data)
		except StopIteration:
			if self.ec is None:
				raise
			self._pull()
		return next(self._data)
	def _enumerate(self):
		self.res = self.p.enumerate(self.resource_uri, selector=self.selector)
		self.root = ET.fromstring(self.res)
		self._get_enumeration_context()
		self._data = None
	def _pull(self):
		pullres =  self.p.pull(self.resource_uri, self.ec, max_elements=self.max_elements)
		self.root = ET.fromstring(pullres)
		self._get_enumeration_context()
		self._data = iter(self.root.find(".//n:Items", namespaces=self.namespaces))
	def _get_enumeration_context(self):
		if self.root.find('.//n:EndOfSequence', namespaces=self.namespaces) is not None:
			self.ec = None
			return
		ecxml = self.root.find('.//n:EnumerationContext', namespaces=self.namespaces)
		if ecxml is None:
			self.ec = None
			return
		self.ec = ecxml.text

def strtodatetime(s):
	return datetime.datetime.now()

class CIMProperty:
	typefunc = {
		'uint8': int,
		'uint16': int,
		'uint32': int,
		'uint64': int,
		'sint8': int,
		'sint16': int,
		'sint32': int,
		'sint64': int,
		'real32': float,
		'real64': float,
		'boolean': lambda x: x == "TRUE",
		'datetime': strtodatetime,
		'char16': lambda x: x.decode('utf-16'),
		'string': str
	}
	def __init__(self, xmldata):
		self._data = xmldata
	def __getattr__(self, key):
		if key.upper() not in self._data.attrib:
			raise AttributeError(key)
		return self._data.attrib[key.upper()]
	@property
	def val(self):
		value_xml = self._data.find('.//VALUE')
		if value_xml is None:
			return None
		value_str = value_xml.text
		return self.typefunc[self.TYPE](value_str)
	def __repr__(self):
		return "<%s name=%s type=%s>" % (self.__class__.__name__, self.name, self.type)

class CIMPropertyArray(CIMProperty):
	def __init__(self, xmldata):
		super(CIMPropertyArray, self).__init__(xmldata)
	@property
	def val(self):
		return None

class CIMPropertyReference(CIMProperty):
	def __init__(self, xmldata):
		super(CIMPropertyReference, self).__init__(xmldata)
	@property
	def val(self):
		return None
	def __repr__(self):
		return "<%s name=%s reference=%s>" % (self.__class__.__name__, self.name, self.REFERENCECLASS)

class CIMClass:
	def __init__(self, xmldata):
		self._data = xmldata
		self._properties = {}
		for p in self._data:
			if p.tag == 'PROPERTY':
				prop = CIMProperty(p)
				self._properties[prop.name] = prop
			elif p.tag == 'PROPERTY.ARRAY':
				prop = CIMPropertyArray(p)
				self._properties[prop.name] = prop
			elif p.tag == 'PROPERTY.REFERENCE':
				prop = CIMPropertyReference(p)
				self._properties[prop.name] = prop
			else:
				raise TypeError
	def __getattr__(self, key):
		if key in self._data.attrib:
			return self._data.attrib[key]
		if key in self._properties:
			return self._properties[key]
		raise AttributeError(key)

from sammwr.wmi import WMIQuery
# DNS Statistics
dns_class_names = [
	"Win32_PerfRawData_DNS_DNS"
]

# AD Statistics
ad_class_names = [
	"Win32_PerfRawData_DirectoryServices_DirectoryServices",
	"Win32_PerfRawData_NTDS_NTDS",
	"Win32_PerfRawData_Lsa_SecuritySystemWideStatistics"
]

# Certification authority
adcs_class_names = [
	"Win32_PerfRawData_CertSvc_CertificationAuthority"
]

# ADFS
adfs_class_names = [
	"Win32_PerfRawData_GenevaServerProvider_ADFS"
]


# Cache
cache_class_names = [
	"Win32_PerfRawData_PerfOS_Cache"
]

# DFS
dfs_class_names = [
	"Win32_PerfRawData_DFSNServerService_DFSNamespace",
	"Win32_PerfRawData_DFSNServerService_DFSNamespaceServiceAPIRequests",
	"Win32_PerfRawData_DFSNServerService_DFSNamespaceServiceReferrals",
	"Win32_PerfRawData_dfsr_DFSReplicatedFolders",
	"Win32_PerfRawData_dfsr_DFSReplicationConnections",
	"Win32_PerfRawData_dfsr_DFSReplicationServiceVolumes"
]

# DHCP
dhcp_class_names = [
	"Win32_PerfRawData_dhcpserver_DHCPServer",
	"Win32_PerfRawData_dhcpserver_DHCPServerv6"
]

# Web Server
web_class_names = [
	"Win32_PerfRawData_W3SVC_WebService"
]

# TS
ts_class_names = [
	"Win32_PerfRawData_TermService_TerminalServicesSession",
	"Win32_PerfRawData_LocalSessionManager_TerminalServices"
]

class_name="Win32_LoggedOnUser"
q=WMIQuery(class_name=class_name, namespace="root/cimv2", protocol=c)
data = list(q)
len(data)
data
