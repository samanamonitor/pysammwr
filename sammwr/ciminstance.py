import re
import xml.etree.ElementTree as ET
from .protocol import SoapFault, WRProtocol
from .utils import tagns, get_xml_namespaces
import logging
from datetime import datetime

log = logging.getLogger(__name__)
ns = {
	"xsi": "http://www.w3.org/2001/XMLSchema-instance"
}

schema_cache = {}
newschema_cache = {}

def cache():
	return newschema_cache

class CimClass:
	xmlns="http://schemas.dmtf.org/wbem/wscim/1/common"
	def dict(self):
		if self.value is None:
			return { 
				"@xsi:type": self.type_name,
				"@xsi:nil": "true" 
			}
		return {
			"@xmlns:cim": self.xmlns,
			"@xsi:type": self.type_name,
			"#text": str(self.value)
		}
	def __str__(self):
		if self.value is None:
			return ""
		return str(self.value)
	def __repr__(self):
		return self.value.__repr__()

class CimString(CimClass):
	type_name="cim:cimString"
	def __init__(self, value):
		if isinstance(value, CimString):
			self.value = value.value
		elif isinstance(value, str):
			self.value = value
		elif isinstance(value, ET.Element):
			nil = bool(value.attrib.get(f"{{{ns['xsi']}}}nil", "false"))
			if nil:
				self.value = None
				return
			self.value = value.text
		elif value is None:
			self.value = value
		else:
			raise TypeError(self.__class__.__name__, value.__class__.__name__)

class CimBoolean(CimClass):
	type_name="cim:cimBoolean"
	def __init__(self, value):
		if isinstance(value, CimBoolean):
			self.value = value.value
		elif isinstance(value, bool):
			self.value = value
		elif isinstance(value, str):
			self.value = bool(value)
		elif isinstance(value, ET.Element):
			nil = bool(value.attrib.get(f"{{{ns['xsi']}}}nil", "false"))
			if nil:
				self.value = None
				return
			self.value = bool(value.text)
		elif value is None:
			self.value = value
		else:
			raise TypeError(self.__class__.__name__, value.__class__.__name__)

class CimInt(CimClass):
	type_name="cim:cimInt"
	def __init__(self, value):
		if isinstance(value, CimInt):
			self.value = value.value
		elif isinstance(value, int):
			self.value = value
		elif isinstance(value, str):
			try:
				self.value = int(value)
			except ValueError("Invalid int ", value) as e:
				log.error(e)
				self.value = -1
		elif isinstance(value, ET.Element):
			nil = bool(value.attrib.get(f"{{{ns['xsi']}}}nil", "false"))
			if nil:
				self.value = None
				return
			try:
				self.value = int(value.text)
			except ValueError("Invalid int ", value.text) as e:
				log.error(e)
				self.value = -1
		elif value is None:
			self.value = value
		else:
			raise TypeError(self.__class__.__name__, value.__class__.__name__)

class CimUnsignedInt(CimInt):
	type_name="cim:cimUnsignedInt"

class CimDateTime(CimClass):
	type_name="cim:cimDateTime"
	def __init__(self, value):
		if isinstance(value, CimDateTime):
			self.value = value.value
			return
		elif isinstance(value, ET.Element):
			nil = bool(value.attrib.get(f"{{{ns['xsi']}}}nil", "false"))
			if nil:
				self.value = None
				return
			dt = value.find("{*}Datetime")
			if dt is None:
				self.value = None
			self.value = datetime.fromisoformat(dt.text)
		elif value is None:
			self.value = value
		self.value = "undefined"

	def dict(self):
		if self.value is None:
			return { 
				"@xsi:type": self.type_name,
				"@xsi:nil": "true" 
			}
		return {
			"@xmlns:cim": self.xmlns,
			"@xsi:type": self.type_name,
			"#text": datetime.isoformat(self.value)
		}

cim_types={
	"boolean": CimBoolean,
	"datetime": CimDateTime,
	"sint16": CimInt,
	"sint32": CimInt,
	"sint64": CimInt,
	"string": CimString,
	"uint16": CimUnsignedInt,
	"uint32": CimUnsignedInt,
	"uint64": CimUnsignedInt,
	"uint8": CimUnsignedInt
}

class CimParamProp:
	def __init__(self, root):
		self.root = root
		self.name = root.attrib.get('NAME')
		self.value_type = root.attrib.get('TYPE')
		self.type = None
		self.cim_type = cim_types.get(self.value_type)
		if self.cim_type is None:
			raise TypeError(f"Invalid cim_type {self.typename} data={ET.tostring(root)}")
		if len(root.tag) < len(self.typename):
			raise TypeError(f"Invalid tag {self.typename} data={ET.tostring(root)}")
		tag = root.tag[len(self.typename):]
		if tag == "":
			self.type = "singleton"
		elif root.tag == "PROPERTY.ARRAY":
			self.type = 'array'
		elif root.tag == "PROPERTY.REFERENCE":
			self.type == 'reference'
		else:
			raise TypeError(f"Invalid type {self.typename} data={ET.tostring(root)}")

	def __repr__(self):
		return f"<{self.__class__.__name__} name={self.name} value_type={self.value_type} type={self.type} cim_type={self.cim_type.__name__}>"

class CimProperty(CimParamProp):
	typename="PROPERTY"

class CimParameter(CimParamProp):
	typename="PARAMETER"

class CimMethod:
	def __init__(self, root):
		self.root = root
		self.name = root.attrib.get('NAME')
		self.value_type = root.attrib.get('TYPE')
		self.parameters = {}
		for param in self.root:
			if param.tag[:len("PARAMETER")] == "PARAMETER":
				_param = CimParameter(param)
				_ = self.parameters.setdefault(_param.name, _param)

	@property
	def params(self):
		return [ param for param in self.parameters ]

	def __repr__(self):
		return f"<{self.__class__.__name__} name='{self.name}' value_type='{self.value_type}' params={str(self.params)}>"

class CimClassSchema:
	def __init__(self, cimnamespace, root):
		self.root = root
		self.cimnamespace = cimnamespace
		self.name = root.attrib.get('NAME')
		self.property = {}
		self.method = {}
		for i in self.root:
			if i.tag[:len("PROPERTY")] == "PROPERTY":
				prop = CimProperty(i)
				_ = self.property.setdefault(prop.name, prop)
			elif i.tag[:len("METHOD")] == "METHOD":
				method = CimMethod(i)
				_ = self.method.setdefault(method.name, method)

	@property
	def props(self):
		return [ pname for pname in self.property ]

	@property
	def methods(self):
		return [ mname for mname in self.method ]

	def __getattr__(self, key):
		prop = self.property.get(key)
		if prop is not None:
			return prop
		method = self.method.get(key)
		if method is not None:
			return method
		raise AttributeError(f"{key} is not a property or a method in class '{self.name}' cimnamespace '{self.cimnamespace}'.")

	def __repr__(self):
		return f"<{self.__class__.__name__} cimnamespace='{self.cimnamespace}' name='{self.name}' properties={self.props} methods={self.methods}>"

def NewCimInstance(type, value):
	if type is None:
		raise TypeError("Invalid type 'None'")
	elif isinstance(value, CimClass):
		return value
	cl = cim_types.get(type)
	if cl is None:
		raise TypeError(type)
	return cl(value)

def xsitype_to_class_name(s):
	typelist = s.split(":")
	class_name = typelist[0]
	if len(typelist) > 1:
		class_name = typelist[1]
	if "_Type" in class_name:
		class_name = class_name[:-len("_Type")]
	return class_name

def NewCimInstanceXml(type, xe, cimnamespace=None, protocol=None):
	if type is None:
		raise TypeError("Invalid type 'None'")

	if isinstance(value, CimClass):
		return value

	xsitype = xe.attrib.get(f"{{{ns['xsi']}}}type")
	if xsitype is not None and type == 'string':
		class_name = xsitype_to_class_name(xsitype)
		return CimInstance(cimnamespace, class_name, xml=xe, protocol=protocol)

	cl = cim_types.get(type)
	if cl is None:
		raise TypeError("type not defined " + type)

class CimInstance(CimClass):
	def __init__(self, cimnamespace, class_name=None, xml=None, protocol=None, **kwargs):
		if protocol is None:
			proto_kwargs = {}
			proto_keys = [ 'endpoint','transport','username','password','realm','service',
				'keytab','ca_trust_path','cert_pem','cert_key_pem','server_cert_validation',
				'kerberos_delegation','read_timeout_sec','operation_timeout_sec',
				'kerberos_hostname_override','message_encryption','credssp_disable_tlsv1_2',
				'send_cbt','proxy']
			for k in proto_keys:
				if k in kwargs:
					proto_kwargs[k] = kwargs.pop(k)
			self.p = WRProtocol(**proto_kwargs)

		else:
			self.p = protocol

		self.cimnamespace = cimnamespace
		self.ns = "p1"
		self.properties = {}
		self.class_name = self._get_class_name(xml, class_name)

		if self.cimnamespace is None or self.class_name is None:
			raise TypeError("Must define 'cimnamespace' and 'class_name'.")

		self._get_schema_xml(self.cimnamespace, self.class_name)

		if xml is not None:
			self._from_xml(xml)
		else:
			for prop_name, prop_value in kwargs.items():
				self.set(prop_name, prop_value)

	@property
	def schema_uri(self):
		return f"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/{self.class_name}"

	@property
	def resource_uri(self):
		return f"http://schemas.microsoft.com/wbem/wsman/1/wmi/{self.cimnamespace}/{self.class_name}"

	def _get_class_name(self, element, class_name):
		if element is None:
			return class_name
		etype = element.attrib.get(f"{{{ns['xsi']}}}type")
		if etype is None:
			return class_name
		return xsitype_to_class_name(etype)

	def _from_xml(self, xml):
		for prop in xml:
			self.set_xml(prop)

	@property
	def props(self):
		out = [ name.attrib.get("NAME") for name in self.schema.findall(".//PROPERTY") ]
		out += [ name.attrib.get("NAME") for name in self.schema.findall(".//PROPERTY.ARRAY") ]
		return out

	@property
	def methods(self):
		return [ name.attrib.get("NAME") for name in self.schema.findall(".//METHOD") ]

	def run_method(self, method_name, **kwargs):
		properties = {}
		method = self.schema.find(f".//METHOD[@NAME='{method_name}']")
		if method is None:
			raise AttributeError(method_name)
		for prop_name, prop_value in kwargs.items():
			method_param = method.find(f".//PARAMETER[@NAME='{prop_name}']")
			is_list = False
			if method_param is None:
				is_list = True
				method_param = method.find(f".//PARAMETER.ARRAY[@NAME='{prop_name}']")
			if method_param is None:
				raise AttributeError(prop_name)
			prop_type = method_param.attrib.get('TYPE')
			if prop_type is None:
				raise AttributeError(f"Schema invalid. Property {prop_name} of method {method_name} in schema doesn't have type")
			value = NewCimInstance(prop_type, prop_value)
			if not is_list:
				properties[prop_name] = value
			else:
				properties.setdefault(prop_name, []).append(value)
		try:
			ret = self.p.execute_method(self.cimnamespace, self.schema_uri, method_name, **properties)
			root = ET.fromstring(ret)
			output = root.find(f".//p:{method_name}_OUTPUT", {"p": self.schema_uri})
			return_value_e = output.find("p:ReturnValue", {"p": self.schema_uri})
			return_value = None
			if return_value_e is not None:
				try:
					return_value = int(return_value_e.text)
				except:
					return_value = None
			namespaces=get_xml_namespaces(ret.decode("utf-8"))
			cmdletOutput=output.find("p:cmdletOutput", {"p": self.schema_uri})
			itype_ns=cmdletOutput.attrib.get("{http://www.w3.org/2001/XMLSchema-instance}type")
			if itype_ns is None:
				raise TypeError("Missing 'type' attribute. cmdletOutput: "+ ET.tostring(cmdletOutput))
			itype_re = re.match(r"([^:]+):(.+)_Type", itype_ns)
			if itype_re is None:
				raise TypeError("Invalid 'type' attribute.cmdletOutput: "+ ET.tostring(cmdletOutput))
			class_name = itype_re.group(2)
			log.debug(f"{self.cimnamespace}/{class_name}")
			instance = CimInstance(self.cimnamespace, class_name, cmdletOutput, protocol=self.p)
			return return_value, instance
		except SoapFault as sf:
			raise self._soap_fault(sf)

	def set_xml(self, prop):
		_, prop_name = tagns(prop.tag)

		schema_prop = getattr(self.newschema, prop_name)

		xsitype = prop.attrib.get(f"{{{ns['xsi']}}}type")
		if xsitype is not None and schema_prop.cim_type.__name__ == 'CimString':
			log.debug(prop.attrib)
			class_name = xsitype_to_class_name(xsitype)
			value = CimInstance(self.cimnamespace, class_name, xml=prop, protocol=self.protocol)
		else:
			value = schema_prop.cim_type(prop)

		if schema_prop.type == 'array':
			_ = self.properties.setdefault(prop_name, []).append(value)
		else:
			self.properties.setdefault(prop_name, value)
		return value

	def set(self, prop_name, prop_value):
		schema_prop = getattr(self.newschema, prop_name)
		value = schema_prop.cim_type(prop)

		if schema_prop.type == 'array':
			_ = self.properties.setdefault(prop_name, []).append(value)
		else:
			self.properties.setdefault(prop_name, value)
		return value

	def dict(self):
		out = {}
		for k, v in self.properties.items():
			value = v
			if isinstance(v, CimClass):
				value = v.dict()
			elif isinstance(v, list):
				value = [ cv.dict() for cv in v ]
			out[f"{self.ns}:{k}"] = value
		out[f"@xmlns:{self.ns}"] = self.schema_uri
		out["@xsi:type"] = f"{self.ns}:{self.class_name}_Type"	
		return out

	def __getattr__(self, attr):
		if attr not in self.props:
			raise AttributeError(attr)
		value = self.properties.get(attr)
		if isinstance(value, CimClass):
			return value.value
		elif isinstance(value, list):
			return value
		return value

	def __repr__(self):
		return f"<{self.cimnamespace}/{self.class_name}>" + self.properties.__repr__()

	def _get_schema_xml(self, cimnamespace, class_name):
		schema_uri='http://schemas.dmtf.org/wbem/cim-xml/2/cim-schema/2/*'
		cache_key = "_".join(["schema", cimnamespace, class_name])
		schema_str = schema_cache.get(cache_key)
		self.newschema = newschema_cache.get(cache_key)
		if self.newschema is None:
			try:
				schema_str = self.p.get(schema_uri, selector=[{
						'@Name': '__cimnamespace',
						'#text': cimnamespace
					},
					{
						'@Name': 'ClassName',
						'#text': class_name
					}])
				schema_cache[cache_key] = schema_str
				schema_root=ET.fromstring(schema_str)
				self.schema =  schema_root.find(".//CLASS")
				self.newschema = newschema_cache.setdefault(cache_key, CimClassSchema(cimnamespace, self.schema))
				newschema_cache.setdefault(cache_key, self.newschema)
			except SoapFault as sf:
				raise self._soap_fault(sf)
		else:
			log.debug("Cache hit for %s", cache_key)

	def get(self):
		selectors = []
		for k, v in self.properties.items():
			if v is not None:
				selectors.append({
					'@Name': k,
					'#text': str(v)
					})
		try:
			res = self.p.get(self.resource_uri, selector=selectors)
			root = ET.fromstring(res)
			obj = root.find(".//{http://www.w3.org/2003/05/soap-envelope}Body/")
			self._from_xml(obj)
		except SoapFault as sf:
			raise self._soap_fault(sf)

	def delete(self, properties=[]):
		selectors = []
		for k in properties:
			v = self.properties.get(k)
			if v is not None:
				selectors.append({
					'@Name': k,
					'#text': str(v)
					})
		try:
			res = self.p.delete(self.resource_uri, selector=selectors)
			return res
		except SoapFault as sf:
			raise self._soap_fault(sf)

	def _soap_fault(self, sf):
		fault_detail = ""
		wmfe = None
		wmie = None
		for i in sf.detail:
			ns, tag = tagns(i.tag)
			if tag == "FaultDetail":
				fault_detail = i.text
			elif tag == "WSManFault":
				wmfe = WsManFault(i, ns, sf)
			elif tag == "MSFT_WmiError":
				try:
					errinst=CimInstance('root','MSFT_WmiError', xml=i, protocol=self.p)
					wmie = MSFT_WmiError(errinst, wmfe, sf)
				except Exception:
					wmie=None
					pass
		if wmie is not None:
			raise wmie
		if wmfe is not None:
			raise wmfe
		raise sf
	def __str__(self):
		return self.__repr__()
	def __iter__(self):
		return CimInstanceIterator(self.cimnamespace, self.class_name, self.p)

class CimInstanceIterator:
	def __init__(self, cimnamespace, class_name, protocol):
		self.cimnamespace = cimnamespace
		self.class_name = class_name
		self.protocol = protocol
		self.ec, self.items = self.enumerate()
	@property
	def resource_uri(self):
		return f"http://schemas.microsoft.com/wbem/wsman/1/wmi/{self.cimnamespace}/{self.class_name}"
	def __next__(self):
		if len(self.items) == 0:
			if self.ec is None:
				raise StopIteration
			(self.ec, self.items) = self.pull(self.ec)
		i = self.items.pop()
		return CimInstance(self.cimnamespace, self.class_name, 
			xml=i, protocol=self.protocol)
	def enumerate(self, max_elements=50, selector=None):
		_txt_enum = self.protocol.enumerate(self.resource_uri, optimize=True, 
			max_elements=max_elements, selector=selector)
		_xml_enum = ET.fromstring(_txt_enum)
		items = _xml_enum.findall('.//{*}Items/')
		_ec = _xml_enum.find('.//wsen:EnumerationContext', self.protocol.xmlns).text
		return _ec, items
	def pull(self, ec):
		_txt_pull = self.protocol.pull(self.resource_uri, ec,max_elements=50)
		_xml_pull = ET.fromstring(_txt_pull)
		items = _xml_pull.findall('.//{*}Items/')
		ec_node = _xml_pull.find('.//wsen:EnumerationContext',self.protocol.xmlns)
		if ec_node is not None:
			_ec = ec_node.text
		else:
			_ec = None
		return _ec, items

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsman/0d0e65bf-e458-4047-8065-b401dae2023e
class WsManFault(Exception):
	def __init__(self, wmf_detail, ns, soap_fault):
		self.detail = wmf_detail.text
		self.code = wmf_detail.attrib.get('Code')
		self.machine = wmf_detail.attrib.get('Machine')
		self.message = wmf_detail.find('f:Message', { "f": ns })
		self.provider_fault = None
		if len(self.message) == 0:
			self.message = self.message.text
		else:
			for m in self.message:
				ns, tag = tagns(m.tag)
				if tag == "ProviderFault":
					self.provider_id=m.attrib.get("providerId")
					self.provider=m.attrib.get("provider")
					self.path = m.attrib.get("path")
					wsmf = m.find("./")
					if wsmf is None:
						self.provider_fault = None
						continue
					_, faulttag = tagns(wsmf.tag)
					if faulttag == "WSManFault":
						self.provider_fault = WsManFault(wsmf, ns, soap_fault)
		fault_list = []
		fault_list.append(f"WsManFault: detail='{self.detail}', code='{self.code}'" + 
			f", machine='{self.machine}' ")
		if self.provider_fault is not None:
			fault_list.append(f"   Provider: id='{self.provider_id}', " +
				f"provider='{self.provider}', path='{self.path}'")
		if self.provider_fault is not None:
			fault_list.append(f"      Inner Fault: {str(self.provider_fault)}")
		super().__init__("\n".join(fault_list))

class MSFT_WmiError(Exception):
	def __init__(self, err_instance, wsman_fault=None, soap_fault=None):
		self.soap_fault=soap_fault
		self.wsman_fault=wsman_fault
		fault_list=[]
		if soap_fault is not None:
			fault_list.append(str(soap_fault))
		if wsman_fault is not None:
			fault_list.append(str(wsman_fault))
		self.cim = err_instance
		fault_list.append(f"WMI Error({self.cim.MessageID}): {self.cim.Message}")
		super().__init__("\n".join(fault_list))
