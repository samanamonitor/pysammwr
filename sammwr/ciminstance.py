import re
import xml.etree.ElementTree as ET
from .protocol import WRProtocol
from .utils import tagns
import logging
from datetime import datetime
from .error import SoapFault, WsManFault
from .wsmprotocol import WSMClient, WSMRequest, WSMGetRequest, WSMEnumerateRequest, WSMPullRequest, SelectorSet, OptionSet, WSMFault, NsMsWsMan, NsXSI, SoapTag, EnumFilter, DIALECT_SELECTOR, DIALECT_WQL

log = logging.getLogger(__name__)
ns = {
	"xsi": "http://www.w3.org/2001/XMLSchema-instance"
}

schema_cache = {}

def cache():
	return schema_cache

class NsCim(SoapTag):
	ns="http://schemas.dmtf.org/wbem/wscim/1/common"

class CimClass:
	xmlns="http://schemas.dmtf.org/wbem/wscim/1/common"
	value = "undefined"

	def xml(self, tag, include_type=True, include_cim_namespace=True, no_text=False, outer_namespace=None):
		if outer_namespace is not None:
			tag = f"{{{outer_namespace}}}{tag}"
		out = ET.Element(tag)
		if include_type:
			out.set(NsXSI("type"), self.type_name)
		if include_cim_namespace:
			out.set("xmlns:cim","http://schemas.dmtf.org/wbem/wscim/1/common" )

		if self.value is None:
			out.set(NsXSI("nil"), "true")
		elif no_text:
			pass
		else:
			out.text = str(self)
		return out

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
			nil = value.attrib.get(f"{{{ns['xsi']}}}nil", "false").lower() == "true"
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
			self.value = value.lower() == 'true'
		elif isinstance(value, ET.Element):
			nil = value.attrib.get(f"{{{ns['xsi']}}}nil", "false").lower() == "true"
			if nil:
				self.value = None
				return
			self.value = value.text.lower() == "true"
		elif value is None:
			self.value = value
		else:
			raise TypeError(self.__class__.__name__, value.__class__.__name__)
	def __str__(self):
		return str(self.value).lower()

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
			nil = value.attrib.get(f"{{{ns['xsi']}}}nil", "false").lower() == "true"
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
			nil = value.attrib.get(f"{{{ns['xsi']}}}nil", "false").lower() == "true"
			if nil:
				self.value = None
				return
			dt = value.find("{*}Datetime")
			if dt is None:
				self.value = None
			self.value = datetime.fromisoformat(dt.text)
			return
		elif value is None:
			self.value = value
			return

	def xml(self, tag, **kwargs):
		out = super().xml(tag, no_text=True, **kwargs)
		dt = ET.SubElement(out, "cim:Datetime")
		if self.value is not None:
			dt.text = datetime.isoformat(self.value)
		return out

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
		self.is_key = False
		key_temp = root.find(".//QUALIFIER[@NAME='key']/VALUE")
		if key_temp is not None:
			self.is_key = (key_temp.text.lower() == "true")
		if self.cim_type is None:
			raise TypeError(f"Invalid cim_type {self.typename} data={ET.tostring(root).decode("utf-8")}")
		if len(root.tag) < len(self.typename):
			raise TypeError(f"Invalid tag {self.typename} data={ET.tostring(root).decode("utf-8")}")
		tag = root.tag[len(self.typename):]
		if tag == "":
			self.type = "singleton"
		elif root.tag == self.typename + ".ARRAY":
			self.type = 'array'
		elif root.tag == self.typename + ".REFERENCE":
			self.type == 'reference'
		else:
			raise TypeError(f"Invalid type {self.typename} data={ET.tostring(root).decode("utf-8")}")
		self._qualifiers = {}
		for q in self.root.findall("QUALIFIER"):
			q_name = q.attrib.get("NAME", "").lower()
			q_type = q.attrib.get("TYPE", "").lower()
			q_value = None
			v = q.find("VALUE.ARRAY")
			if v is not None:
				q_value = [ NewCimInstance(q_type, val.text) for val in v.findall("VALUE") ]
			else:
				q_value = NewCimInstance(q_type, q.find("VALUE"))
			_ = self._qualifiers.setdefault(q_name, q_value)

	def __repr__(self):
		return f"<{self.__class__.__name__} name={self.name} value_type={self.value_type} type={self.type} cim_type={self.cim_type.__name__}>"

class CimProperty(CimParamProp):
	typename="PROPERTY"

class CimParameter(CimParamProp):
	typename="PARAMETER"

class CimMethodSchema:

	def __init__(self, root):
		self.root = root
		self.name = root.attrib.get('NAME')
		self.value_type = root.attrib.get('TYPE')
		self._parameters = {}
		for param in self.root:
			if param.tag[:len("PARAMETER")] == "PARAMETER":
				_param = CimParameter(param)
				_ = self._parameters.setdefault(_param.name, _param)

	@property
	def params(self):
		return [ param for param in self._parameters ]

	def __getattr__(self, attr):
		param = self._parameters.get(attr)
		if param is None:
			raise AttributeError("Parameter " + attr + " not defined in method " + self.name)
		return param

	def __repr__(self):
		return f"<{self.__class__.__name__} name='{self.name}' value_type='{self.value_type}' params={str(self.params)}>"

class CimClassSchema:
	def __init__(self, cimnamespace, root):
		if not isinstance(root, ET.Element):
			raise TypeError("root")
		self.root = root
		self.cimnamespace = cimnamespace
		self.name = root.attrib.get('NAME')
		self._property = {}
		self._method = {}
		self._property_keys = {}
		for i in self.root:
			if i.tag[:len("PROPERTY")] == "PROPERTY":
				prop = CimProperty(i)
				if prop.is_key:
					self._property_keys.setdefault(prop.name, prop)
				_ = self._property.setdefault(prop.name, prop)
			elif i.tag[:len("METHOD")] == "METHOD":
				method = CimMethodSchema(i)
				_ = self._method.setdefault(method.name, method)

	@property
	def props(self):
		return [ pname for pname in self._property ]

	@property
	def methods(self):
		return [ mname for mname in self._method ]

	def __getattr__(self, key):
		prop = self._property.get(key)
		if prop is not None:
			return prop
		method = self._method.get(key)
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
	def __init__(self, cimnamespace, class_name=None, xml=None, protocol=None, wqlfilter=None, **kwargs):
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

		self.wsmclient = WSMClient(self.p.transport)
		self.cimnamespace = cimnamespace
		self.ns = "p1"
		self._properties = {}
		self._newschema = None
		self.class_name = self._get_class_name(xml, class_name)
		self._wqlfilter = wqlfilter
		self.type_name = self.resource_uri

		if self.cimnamespace is None or self.class_name is None:
			raise TypeError("Must define 'cimnamespace' and 'class_name'.")

		self._get_schema_xml(self.cimnamespace, self.class_name)

		if isinstance(xml, ET.Element):
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
		self._xml = xml
		for prop in xml:
			self.set_xml(prop)

	@property
	def props(self):
		return self._newschema.props

	@property
	def methods(self):
		return self._newschema.methods

	def _get_selector(self):
		selector = [
			{
				"@Name": "__cimnamespace",
				"#text": self.cimnamespace
			}]
		for key_name in self._newschema._property_keys:
			value = self._properties.get(key_name)
			if value is None:
				continue
				raise AttributeError(f"Attribute {key_name} doesn't have a value")
			selector.append({
				"@Name": key_name,
				"#text": value
				})
		return selector

	def _parameters_to_cim(self, schema_method, **kwargs):
		parameters = {}

		for param_name, param_value in kwargs.items():
			# TODO validate that input is of correct type based on embeddedinstance qualifier
			param = getattr(schema_method, param_name)
			if isinstance(param_value, CimClass):
				value = param_value
			elif isinstance(param_value, list):
				value = param_value
			else:
				value = param.cim_type(param_value)
			if param.type == 'singleton':
				_ = parameters.setdefault(param_name, value)
			elif param.type == 'array':
				if isinstance(param_value, list):
					_ = parameters.setdefault(param_name, value)
				else:
					_ = parameters.setdefault(param_name, []).append(value)
		return parameters

	def run_method(self, method_name, **kwargs):

		schema_method = getattr(self._newschema, method_name)

		if schema_method is None:
			raise AttributeError("Method " + method_name + " not defined")

		parameters = self._parameters_to_cim(schema_method, **kwargs)
		try:
			selectors = self._get_key_selectors()
			action = f"{self.schema_uri}/{method_name}"
			req = WSMRequest(action, self.schema_uri, selector_set=selectors)
			ns=f"{{{self.schema_uri}}}"
			m_input = ET.SubElement(req.body, f"{ns}{method_name}_INPUT")
			m_input.set(NsXSI("type"), f"{method_name}_INPUT_Type")
			for k, v in parameters.items():
				if isinstance(v, list):
					for i in v:
						m_input.append(i.xml(f"{ns}{k}", include_cim_namespace=False))
				else:
					m_input.append(v.xml(f"{ns}{k}", include_cim_namespace=False))

			req._ready = True
			res = self.wsmclient.do(req)
			output = res.Body.find(f"{{*}}{method_name}_OUTPUT")
			return_value_e = output.find("{*}ReturnValue")
			return_value = None
			if return_value_e is not None:
				try:
					return_value = int(return_value_e.text)
				except:
					return_value = None
			out_params = {}
			for _, param in schema_method._parameters.items():
				if param._qualifiers.get('out', False):
					output_param=output.find(f"{{*}}{param.name}")
					if output_param is None:
						continue
					embedded_instance = param._qualifiers.get("embeddedinstance")
					if embedded_instance is not None:
						# TODO Validate expected embedded instance
						#itype_ns=output_param.attrib.get("{http://www.w3.org/2001/XMLSchema-instance}type")
						#if itype_ns is None:
						#	raise TypeError("Missing 'type' attribute. output_param: "+ ET.tostring(output_param))
						#itype_re = re.match(r"([^:]+):(.+)_Type", itype_ns)
						#if itype_re is None:
						#	raise TypeError("Invalid 'type' attribute.output_param: "+ ET.tostring(output_param))
						#class_name = itype_re.group(2)
						instance = CimInstance(self.cimnamespace, embedded_instance, output_param, protocol=self.p)
						out_params.setdefault(param.name, instance)
					else:
						out_params.setdefault(param.name, output_param.text)
			return return_value, out_params
		except SoapFault as sf:
			raise self._soap_fault(sf)

	def set_xml(self, prop):
		_, prop_name = tagns(prop.tag)

		schema_prop = getattr(self._newschema, prop_name)

		xsitype = prop.attrib.get(f"{{{ns['xsi']}}}type")
		if xsitype is not None and xsitype[:4] != "cim:" and schema_prop.cim_type.__name__ == 'CimString':
			class_name = xsitype_to_class_name(xsitype)
			value = CimInstance(self.cimnamespace, class_name, xml=prop, protocol=self.p)
		else:
			value = schema_prop.cim_type(prop)

		if schema_prop.type == 'array':
			_ = self._properties.setdefault(prop_name, []).append(value)
		else:
			_ = self._properties.setdefault(prop_name, value)
		return value

	def set(self, prop_name, prop_value):
		schema_prop = getattr(self._newschema, prop_name)
		value = schema_prop.cim_type(prop_value)

		if schema_prop.type == 'array':
			_ = self._properties.setdefault(prop_name, []).append(value)
		else:
			self._properties.setdefault(prop_name, value)
		return value

	def xml(self, tag, outer_namespace=None, **kwargs):
		ns=f"{{{self.resource_uri}}}"
		if outer_namespace is not None:
			tag = f"{{{outer_namespace}}}{tag}"
		else:
			tag = f"{ns}{tag}"
		out = super().xml(tag, no_text=True, **kwargs)
		out.set(NsXSI("type"), f"{self.class_name}_Type")
		for k, v in self._properties.items():
			tag=f"{ns}{k}"
			value = v
			if isinstance(v, CimClass):
				out.append(v.xml(tag, include_type=False, include_cim_namespace=False))
			elif isinstance(v, list):
				for cv in v:
					out.append(cv.xml(tag, include_type=False, include_cim_namespace=False))
		return out

	def dict(self):
		out = {}
		for k, v in self._properties.items():
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
		if attr in self._newschema.methods:
			return lambda *args, **kwargs: self.run_method(attr, *args, **kwargs)
			return getattr(self._newschema, attr)
		if attr not in self._newschema.props:
			raise AttributeError(attr)
		value = self._properties.get(attr)
		if isinstance(value, CimInstance):
			return value
		elif isinstance(value, CimClass):
			return value.value
		elif isinstance(value, list):
			return value
		return value

	def __repr__(self):
		return f"<{self.cimnamespace}/{self.class_name}>" + self._properties.__repr__()

	def _get_schema_xml(self, cimnamespace, class_name):
		#other schema uri?
		# "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/Win32_ComputerSystem"
		log.debug("Getting Schema for cimnamespace='%s' class_name='%s'", cimnamespace, class_name)
		schema_uri='http://schemas.dmtf.org/wbem/cim-xml/2/cim-schema/2/*'
		cache_key = "_".join(["schema", cimnamespace, class_name])
		self._newschema = schema_cache.get(cache_key)
		if self._newschema is None:
			try:
				selector_set=SelectorSet()
				selector_set.addSelector('__cimnamespace', cimnamespace)
				selector_set.addSelector('ClassName', class_name)

				option_set=OptionSet()
				option_set.addOption('IncludeQualifiers', 'xs:boolean', 'true')

				schema_res = self.wsmclient.do(WSMGetRequest(schema_uri,
					selector_set=selector_set, option_set=option_set))

				schema = next(iter(schema_res.Items))
				self._newschema = schema_cache.setdefault(cache_key, 
					CimClassSchema(cimnamespace, schema))

			except SoapFault as sf:
				raise self._soap_fault(sf)
		else:
			log.debug("Cache hit for %s", cache_key)

	def _get_key_selectors(self):
		selectors = SelectorSet()
		selectors.addSelector("__cimnamespace", self.cimnamespace)
		for key_name in self._newschema._property_keys:
			value = self._properties.get(key_name)
			if value is None:
				continue
			selectors.addSelector(key_name, value)
		return selectors

	def get(self):
		selectors = self._get_key_selectors()

		try:
			res = self.wsmclient.do(WSMGetRequest(self.resource_uri, selector_set=selectors))
			for obj in res.Items:
				self._from_xml(obj)
				break
		except SoapFault as sf:
			raise self._soap_fault(sf)

	def delete(self):
		selectors = self._get_key_selectors()
		try:
			res = self.wsmclient.do(WSMDeleteRequest(self.resource_uri, selector_set=selectors))
		except SoapFault as sf:
			raise self._soap_fault(sf)

	def _soap_fault(self, sf):
		if sf.detail.find("{*}MSFT_WmiError"):
			raise MSFT_WmiError(sf, self.p)
		if sf.detail.find("{*}WSManFault"):
			raise WSMFault(sf)
		raise sf

	def __iter__(self):
		return CimInstanceIterator(self)

class CimInstanceIterator:
	def __init__(self, base_instance):
		self.cimnamespace = base_instance.cimnamespace
		self.class_name = base_instance.class_name
		self.protocol = base_instance.p
		self.wsmclient = base_instance.wsmclient
		self.wqlfilter = base_instance._wqlfilter

		enum_filter = None
		resource_uri = self.resource_uri
		if self.wqlfilter is not None:
			wql = f"SELECT * FROM {self.class_name} WHERE {self.wqlfilter}"
			resource_uri = "http://schemas.dmtf.org/wbem/wscim/1/*"
			enum_filter = EnumFilter(DIALECT_WQL, wql=wql, cimnamespace=self.cimnamespace)
		self.res = self.wsmclient.do(WSMEnumerateRequest(resource_uri, enum_filter=enum_filter))
		self.items = self.res.Items

	@property
	def resource_uri(self):
		return f"http://schemas.microsoft.com/wbem/wsman/1/wmi/{self.cimnamespace}/{self.class_name}"

	def __next__(self):
		if len(self.items) == 0:
			if self.res.EndOfSequence:
				raise StopIteration
			self.res = self.wsmclient.do(WSMPullRequest(self.res))
			self.items = self.res.Items
		i = self.items.pop()
		return CimInstance(self.cimnamespace, self.class_name, 
			xml=i, protocol=self.protocol)

class MSFT_WmiError(Exception):
	def __init__(self, soap_fault, protocol):
		if not isinstance(soap_fault, SoapFault):
			raise TypeError("Expecting type SoapFault")
		self.root = soap_fault.detail.find(".//{*}MSFT_WmiError")
		if self.root is None:
			raise TypeError("SoapFault doesn't contain a MSFT_WmiError")
		err_instance=CimInstance('root','MSFT_WmiError', xml=self.root, protocol=protocol)
		self.soap_fault=soap_fault
		fault_list=[]
		if soap_fault is not None:
			fault_list.append(str(soap_fault))
		self.cim = err_instance
		fault_list.append(f"WMI Error({self.cim.MessageID}): {self.cim.Message}")
		super().__init__("\n".join(fault_list))
