import xml.etree.ElementTree as ET
from sammwr.protocol import WRProtocol
from sammwr.wmi import WMIQuery
from sammwr.cimclient import CIMClient
import os
import datetime

username=os.environ['WRUSERNAME']
password=os.environ['WRPASSWORD']
endpoint=os.environ['WRENDPOINT']
c=WRProtocol(username=username, password=password, endpoint=endpoint)

cc=CIMClient(c, selector=[
	{"@Name": "__cimnamespace", "#text": "root/cimv2"}, 
	{"@Name": "classname", "#text":"Win32_OperatingSystem"}
	])


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

def get_namespaces(c, root="Root"):
	''' List all namespaces '''
	ns={
		"e": "http://schemas.xmlsoap.org/ws/2004/09/enumeration",
		"ns": "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/__NAMESPACE"
	}
	resource_uri="http://schemas.microsoft.com/wbem/wsman/1/wmi/%s/__Namespace" % root
	enum=c.enumerate(resource_uri)
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
	return [ x.text for x in r.findall(".//ns:Name", ns)]


#wmi
#http://schemas.microsoft.com/wbem/wsman/1/wmi
#
#wmicimv2
#http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2
#
#cimv2
#https://schemas.dmtf.org/wbem/wscim/1/cim-schema/2
#
#winrm
#http://schemas.microsoft.com/wbem/wsman/1
#
#wsman
#http://schemas.microsoft.com/wbem/wsman/1
#
#shell
#http://schemas.microsoft.com/wbem/wsman/1/windows/shell

# List all classes in a namespace
def get_classes(c, root="root", 
		resource_uri="http://schemas.dmtf.org/wbem/cim-xml/2/cim-schema/2/*",
		selector=[{"@Name": "__cimnamespace", "#text": root}]):
	ns = { "e": "http://schemas.xmlsoap.org/ws/2004/09/enumeration" }
	enum=c.enumerate(resource_uri, selector=selector)
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

class_name="Win32_PerfRawData_CitrixICA_ICASession"
def d(class_name):
	q=WMIQuery(class_name=class_name, namespace="root/cimv2", protocol=c)
	data = list(q)
	print(len(data))
	return data
