import xml.etree.ElementTree as ET


class CIMClient:
	resource_uri="http://schemas.dmtf.org/wbem/cim-xml/2/cim-schema/2/*"
	def __init__(self, protocol, namespace="root", selector=None):
		self.p = protocol
		self.namespace = namespace
		self.selector = selector
	@property
	def classes(self):
		return CIMClassIterator(self)
	def get_class(self, namespace, class_name):
		res = self.p.get(self.resource_uri, selector=[
			{ "@Name": "__cimnamespace", "#text": namespace },
			{ "@Name": "Classname", "#text": class_name } ])
		root = ET.fromstring(res)
		class_xml = root.find(".//CLASS[@NAME='%s']" % class_name)
		return CIMClass(class_xml, self)
	def enumerate(self):
		self.res = self.p.enumerate(self.resource_uri, selector=self.selector)
		return ET.fromstring(self.res)
	def pull(self, enumeration_context, max_elements=10):
		pullres =  self.p.pull(self.resource_uri, enumeration_context, max_elements=max_elements, selector=self.selector)
		return ET.fromstring(pullres)


class CIMClassIterator:
	namespaces={'n': 'http://schemas.xmlsoap.org/ws/2004/09/enumeration'}
	def __init__(self, cimclient, max_elements=10, **kwargs):
		self.cimclient = cimclient
		self.max_elements = max_elements
		self.selector = kwargs.get("selector")
		self._data = None
	def __iter__(self):
		self.root = self.cimclient.enumerate()
		self._data = None
		return self
	def __next__(self):
		if self._data is None:
			self._pull()
		try:
			data = next(self._data)
		except StopIteration:
			if self.ec is None:
				raise
			self._pull()
			data = next(self._data)
		root = ET.fromstring(data)
		class_xml = root.find(".//CLASS[@NAME='%s']" % class_name)
		return CIMClass(class_xml, self)
	def _pull(self):
		if self.root.find('.//n:EndOfSequence', namespaces=self.namespaces) is not None:
			self.ec = None
			return
		ecxml = self.root.find('.//n:EnumerationContext', namespaces=self.namespaces)
		if ecxml is None:
			self.ec = None
			return
		self.ec = ecxml.text
		self.root = self.cimclient.pull(self.ec, self.max_elements)
		self._data = iter(self.root.find(".//n:Items", namespaces=self.namespaces))

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
	def __init__(self, xmldata, cimclient):
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
				print("Unknown tag: %s" % p.tag)
	def __getattr__(self, key):
		if key in self._data.attrib:
			return self._data.attrib[key]
		if key in self._properties:
			return self._properties[key]
		raise AttributeError(key)

class CIMInstance:
	resource_uri="http://schemas.microsoft.com/wbem/wsman/1/wmi"
	pass

