from .protocol import WRProtocol
import logging
import xml.etree.ElementTree as ET

log = logging.getLogger(__name__)

class CimSchema:
	# other option?
	# resource_uri='http://schemas.dmtf.org/wbem/wscim/1/*'
	resource_uri='http://schemas.dmtf.org/wbem/cim-xml/2/cim-schema/2/*'
	def __init__(self, protocol, cimnamespace):
		if not isinstance(protocol, WRProtocol):
			raise TypeError("Attribute protocol must be of WRProtocol type")
		self._protocol = protocol
		self._cimnamespace=cimnamespace
	def __iter__(self):
		self.ec, self.items = self.enumerate(selector=[{"@Name": "__cimnamespace", "#text": self._cimnamespace}])
		return self
	def enumerate(self, max_elements=50, selector=None):
		_txt_enum = self._protocol.enumerate(self.resource_uri, optimize=True, 
			max_elements=max_elements, selector=selector)
		_xml_enum = ET.fromstring(_txt_enum)
		items = _xml_enum.findall('.//{*}Items/')
		_ec = _xml_enum.find('.//wsen:EnumerationContext', self._protocol.xmlns).text
		return _ec, items
	def pull(self, ec):
		_txt_pull = self._protocol.pull(self.resource_uri, ec,max_elements=50)
		_xml_pull = ET.fromstring(_txt_pull)
		items = _xml_pull.findall('.//{*}Items/')
		ec_node = _xml_pull.find('.//wsen:EnumerationContext',self._protocol.xmlns)
		if ec_node is not None:
			_ec = ec_node.text
		else:
			_ec = None
		return _ec, items
	def __next__(self):
		if len(self.items) == 0:
			if self.ec is None:
				raise StopIteration
			(self.ec, self.items) = self.pull(self.ec)
		i = self.items.pop()
		return i


