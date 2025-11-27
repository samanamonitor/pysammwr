# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv/b0a305d5-1c8f-4fc7-a5d1-85de9b00b730
# https://www.dmtf.org/sites/default/files/standards/documents/DSP0226_1.0.0.pdf
# check for filters:
# https://www.dmtf.org/sites/default/files/standards/documents/DSP0227_1.0.0.pdf
import xml.etree.ElementTree as ET
import uuid
from winrm.transport import Transport
from winrm.exceptions import WinRMTransportError
from kerberos import GSSError
import logging
from .error import SoapFault
from .utils import tagns

log = logging.getLogger(__name__)

DIALECT_SELECTOR='http://schemas.dmtf.org/wbem/wsman/1/wsman/SelectorFilter'
DIALECT_WQL='http://schemas.microsoft.com/wbem/wsman/1/WQL'

class SoapTag(str):
	ns = ""
	def __new__(cls, tagname):
		instance = super().__new__(cls, f"{{{cls.ns}}}{tagname}")
		return instance

class NsAddressing(SoapTag):
	ns="http://schemas.xmlsoap.org/ws/2004/08/addressing"

class NsEnvelope(SoapTag):
	ns="http://www.w3.org/2003/05/soap-envelope"

class NsWsMan(SoapTag):
	ns="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"

class NsMsWsMan(SoapTag):
	ns="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"

class NsEnumerate(SoapTag):
	ns="http://schemas.xmlsoap.org/ws/2004/09/enumeration"

class NsXSI(SoapTag):
	ns="http://www.w3.org/2001/XMLSchema-instance"

class SelectorSet(ET.Element):
	def __init__(self):
		super().__init__(NsWsMan("SelectorSet"))
		self._keys = []

	def addSelector(self, key, value):
		sel = ET.SubElement(self, NsWsMan("Selector"))
		sel.set("Name", key)
		sel.text = str(value)
		self._keys.append(f"{key}={value}")

	def __repr__(self):
		return f"<SelectorSet items={self._keys}>"

class OptionSet(ET.Element):
	def __init__(self):
		super().__init__(NsWsMan("OptionSet"))

	def addOption(self, name, type, value):
		opt = ET.SubElement(self, NsWsMan("Option"))
		opt.set("Name", name)
		opt.set("Type", type)
		opt.text = str(value)

class EnumFilter(ET.Element):
	def __init__(self, dialect, selector_set=None, wql=None, cimnamespace=None):
		super().__init__(NsWsMan("Filter"))
		self.set("Dialect", dialect)
		self._cimnamespace = cimnamespace

		if dialect == DIALECT_SELECTOR:
			if not isinstance(selector_set, SelectorSet):
				raise TypeError("Attribute 'selector_set' must be of type SelectorSet")
			self.append(selector_set)

		elif dialect == DIALECT_WQL:
			if not isinstance(wql, str):
				raise TypeError("Attribute 'wql' must be of type str")
			self.text = wql

class WSMClient:
	def __init__(self, transport):
		if not isinstance(transport, Transport):
			raise TypeError("Attribute 'transport' must be of type winrm.Transport")
		self._transport = transport
		self._transpor_retries = 0

	def do(self, request):
		if not isinstance(request, WSMRequest):
			raise TypeError("Attribute 'request' must be of type WSMRequest")
		if not request._ready:
			raise Exception("Not ready")
		if request._response_class is None:
			raise TypeError("This class cannot be used in this way.")
		request.setEndpoint(self._transport.endpoint)
		req = ET.tostring(request.getroot()).decode("utf-8")
		log.debug("Request: %s", req)
		restxt = ""
		while True:
			try:
				restxt = self._transport.send_message(req)
				self._transpor_retries = 0
				log.debug("Response: %s", restxt)
				break

			except WinRMTransportError as ex:
				if ex.response_text == '' and int(ex.code) == 400:
					if self._transpor_retries > 3:
						raise
					self._transpor_retries += 1
					self._transport.session = None
				else:
					log.debug("Error: %s", ex.response_text)
					root= ET.fromstring(ex.response_text)
					fault = root.find("{*}Body/{*}Fault")
					if fault is not None:
						sf = SoapFault(fault)
						wsmf = sf.detail.find("{*}WSManFault")
						if wsmf is not None:
							raise WSMFault(sf)
						raise sf
					raise

			except GSSError as e:
				err_maj = e.args[0][1]
				err_min = e.args[1][1]
				if err_maj == 0x80000 and err_min == 0x25ea107:
					log.warning("Session token has expired. Retrying %d/3", self._transpor_retries)
					if self._transpor_retries > 3:
						raise
					self._transpor_retries += 1
					# Resets the session, so that a retry will create a new session
					# maj = 'No context has been established'
					self._transport.session = None
				else:
					raise

		return request._response_class(restxt, request)

class WSMResponse(ET.ElementTree):
	def __init__(self, xml, request):
		super().__init__(ET.fromstring(xml))
		self._request = request
	def __getattr__(self, item):
		if item == "Body":
			return self.find("{*}Body")
		out = self.find(f"{{*}}Header/{{*}}{item}")
		if out is not None:
			return out.text
		raise AttributeError(item)

class WSMRequest(ET.ElementTree):
	_response_class = WSMResponse
	def __init__(self, action, resource_uri, selector_set=None, option_set=None, max_envelope_size='512000', lang="en-US"):
		self.envelope     = ET.Element(NsEnvelope("Envelope"))
		super().__init__(self.envelope)
		self.header       = ET.SubElement(self.envelope, NsEnvelope("Header"))
		self.body         = ET.SubElement(self.envelope, NsEnvelope("Body"))
		self.to           = ET.SubElement(self.header,   NsAddressing("To"))
		self.resource_uri = ET.SubElement(self.header,   NsWsMan("ResourceURI"))
		self.replyto      = ET.SubElement(self.header,   NsAddressing("ReplyTo"))
		self.address      = ET.SubElement(self.replyto,  NsAddressing("Address"))
		self.action       = ET.SubElement(self.header,   NsAddressing("Action"))
		self.mes          = ET.SubElement(self.header,   NsWsMan("MaxEnvelopeSize"))
		self.message_id   = ET.SubElement(self.header,   NsAddressing("MessageID"))
		self.locale       = ET.SubElement(self.header,   NsWsMan("Locale"))
		self.data_locale  = ET.SubElement(self.header,   NsMsWsMan("DataLocale"))
		self.address.set    (NsEnvelope("mustUnderstand"), "true")
		self.action.set     (NsEnvelope("mustUnderstand"), "true")
		self.mes.set        (NsEnvelope("mustUnderstand"), "true")
		self.locale.set     ("xml:lang", lang)
		self.locale.set     (NsEnvelope("mustUnderstand"), "false")
		self.data_locale.set("xml:lang", lang)
		self.data_locale.set(NsEnvelope("mustUnderstand"), "false")
		if isinstance(selector_set, ET.Element):
			self.header.append(selector_set)
		if isinstance(option_set, ET.Element):
			self.header.append(option_set)
		self.resource_uri.text = resource_uri
		self.to.text = 'http://windows-host:5985/wsman'
		self.address.text = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
		self.action.text = action
		self.mes.text = max_envelope_size
		self.message_id.text = f"uuid:{str(uuid.uuid4()).upper()}"
		self._ready = False
	def setEndpoint(self, endpoint):
		self.to.text = endpoint
	def addSelectorSet(self, selector_set):
		if not isinstance(selector_set, SelectorSet):
			raise TypeError
		self.header.append(selector_set)
	def addOptionSet(self, option_set):
		if not isinstance(option_set, OptionSet):
			raise TypeError
		self.header.append(option_set)
	def setTransport(self, transport):
		if not isinstance(transport, Transport):
			raise TypeError("transport")
		self._transport = transport

class WSMGetResponse(WSMResponse):
	@property
	def Items(self):
		return [self.find("{*}Body/")]

class WSMGetRequest(WSMRequest):
	action="http://schemas.xmlsoap.org/ws/2004/09/transfer/Get"
	_response_class = WSMGetResponse
	def __init__(self, *args, **kwargs):
		super().__init__(self.action, *args, **kwargs)
		self._ready = True

class WSMPutResponse(WSMResponse):
	pass

class WSMPutRequest(WSMRequest):
	action="http://schemas.xmlsoap.org/ws/2004/09/transfer/Put"
	_response_class = WSMPutResponse
	def __init__(self, *args, **kwargs):
		super().__init__(self.action, *args, **kwargs)

class WSMCreateResponse(WSMResponse):
	pass

class WSMCreateRequest(WSMRequest):
	action="http://schemas.xmlsoap.org/ws/2004/09/transfer/Create"
	_response_class = WSMCreateResponse
	def __init__(self, *args, **kwargs):
		super().__init__(self.action, *args, **kwargs)
		self._ready = True

class WSMDeleteResponse(WSMResponse):
	pass

class WSMDeleteRequest(WSMRequest):
	action="http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete"
	_response_class = WSMDeleteResponse
	def __init__(self, *args, **kwargs):
		super().__init__(self.action, *args, **kwargs)
		self._ready = True

class WSMEnumerateResponse(WSMResponse):
	@property
	def Items(self):
		return self.findall("{*}Body/{*}EnumerateResponse/{*}Items/")

	@property
	def EnumerationContext(self):
		out = self.find("{*}Body/{*}EnumerateResponse/{*}EnumerationContext")
		if out is not None:
			return out.text
		return None
	@property
	def EndOfSequence(self):
		return self.find("{*}Body/{*}PullResponse/{*}EndOfSequence") is not None

class WSMEnumerateRequest(WSMRequest):
	action="http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"
	_response_class = WSMEnumerateResponse
	def __init__(self, *args, optimize=False, max_elements=50, enum_filter=None, **kwargs):
		super().__init__(self.action, *args, **kwargs)

		self.enumerate = ET.SubElement(self.body, NsEnumerate("Enumerate"))
		ET.SubElement(self.enumerate, NsWsMan("MaxElements")).text = str(max_elements)

		if optimize:
			ET.SubElement(self.enumerate, NsWsMan("OptimizeEnumeration"))

		if isinstance(enum_filter, ET.Element):
			if enum_filter.get("Dialect") == DIALECT_WQL:
				self.resource_uri.text = "http://schemas.dmtf.org/wbem/wscim/1/*"
				ss = SelectorSet()
				ss.addSelector("__cimnamespace", "root/cimv2")
				self.addSelectorSet(ss)
			self.enumerate.append(enum_filter)
		self._ready = True

class WSMPullResponse(WSMResponse):
	@property
	def Items(self):
		return list(self.find("{*}Body/{*}PullResponse/{*}Items"))
	@property
	def EnumerationContext(self):
		out = self.find("{*}Body/{*}PullResponse/{*}EnumerationContext")
		if out is not None:
			return out.text
		return None
	@property
	def EndOfSequence(self):
		return self.find("{*}Body/{*}PullResponse/{*}EndOfSequence") is not None

class WSMPullRequest(WSMRequest):
	action="http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull"
	_response_class=WSMPullResponse
	def __init__(self, enum_context, *args, max_elements=50, **kwargs):
		if isinstance(enum_context, WSMEnumerateResponse) or isinstance(enum_context, WSMPullResponse):
			resource_uri = enum_context._request.resource_uri.text
			max_envelope_size = enum_context._request.mes.text
			lang = enum_context._request.locale.get("xml:lang")
			ec = enum_context.EnumerationContext
			super().__init__(self.action, resource_uri, max_envelope_size=max_envelope_size, lang=lang)
		elif isinstance(enum_context, str):
			super().__init__(self.action, *args, **kwargs)
			ec = enum_context
		else:
			raise TypeError("enum_context")
		self.pull = ET.SubElement(self.body, NsEnumerate("Pull"))
		ET.SubElement(self.pull, NsEnumerate("EnumerationContext")).text = ec
		ET.SubElement(self.pull, NsEnumerate("MaxElements")).text = str(max_elements)
		if isinstance(enum_context, WSMPullResponse) and enum_context.EndOfSequence:
			self._ready = False
		else:
			self._ready = True

class WSMRenewResponse:
	pass

class WSMRenewRequest(WSMRequest):
	action="http://schemas.xmlsoap.org/ws/2004/09/enumeration/Renew"
	_response_class = WSMRenewResponse
	def __init__(self, *args, **kwargs):
		super().__init__(self.action, *args, **kwargs)
		self._ready = True

class WSMReleaseResponse(WSMResponse):
	pass

class WSMReleaseRequest(WSMRequest):
	action="http://schemas.xmlsoap.org/ws/2004/09/enumeration/Release"
	_response_class=WSMReleaseResponse
	def __init__(self, enum_context, *args, **kwargs):
		if isinstance(enum_context, WSMEnumerateResponse) or isinstance(enum_context, WSMPullResponse):
			resource_uri = enum_context._request.resource_uri.text
			max_envelope_size = enum_context._request.mes.text
			lang = enum_context._request.locale.get("xml:lang")
			ec = enum_context.EnumerationContext
			super().__init__(self.action, resource_uri, max_envelope_size=max_envelope_size, lang=lang)
		else:
			ec = enum_context
			super().__init__(self.action, *args, **kwargs)
		self.pull = ET.SubElement(self.body, NsEnumerate("Release"))
		ET.SubElement(self.pull, NsEnumerate("EnumerationContext")).text = ec
		self._ready = True

class WSMGetStatusResponse(WSMResponse):
	pass

class WSMGetStatusRequest(WSMRequest):
	action="http://schemas.xmlsoap.org/ws/2004/09/enumeration/GetStatus"
	_response_class = WSMGetStatusResponse
	def __init__(self, *args, **kwargs):
		super().__init__(self.action, *args, **kwargs)

class WSMMethodResponse(WSMResponse):
	pass

class WSMMethodRequest(WSMRequest):
	pass

class ProviderFault(Exception):
	def __init__(self, element):
		if not isinstance(element, ET.Element):
			raise TypeError("element")
		if "ProviderFault" not in element.tag:
			raise TypeError(f"Expecting 'ProviderFault' tag and received {element.tag}")
		self.root = element
		outstr = []
		for k, v in element.attrib.items():
			outstr.append(f"{k}='{v}'")
		self.innerFaults = []
		for i in element:
			if "WSManFault" in i.tag:
				print(i.tag)
				self.innerFaults.append(f"\n{str(WSMFault(i))}")
			elif "ExtendedError" in i.tag:
				status = i.find("{*}__ExtendedStatus")
				if status is None: continue
				ee = []
				for d in status:
					_, tag = tagns(d.tag)
					ee.append(f"{tag}='{d.text}'")
				self.innerFaults.append("ExtendedError:\n\t" + "\n\t".join(ee))
		outstr.append("\n".join(self.innerFaults))
		super().__init__("ProviderFault: " + " ".join(outstr))

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsman/0d0e65bf-e458-4047-8065-b401dae2023e
class WSMFault(Exception):
	def __init__(self, soap_fault):
		if not isinstance(soap_fault, SoapFault):
			raise TypeError("Expecting type 'SoapFault'")
		self.root=soap_fault.detail.find(".//{*}WSManFault")
		if self.root is None:
			raise TypeError("SoapFault doesn't contain a WSManFault")
		self.detail = self.root.text
		self.code = self.root.attrib.get('Code')
		self.machine = self.root.attrib.get('Machine')
		self.message = self.root.find('{*}Message')
		self.provider_fault = None
		if len(self.message) == 0:
			self.message = self.message.text
		else:
			for m in self.message:
				ns, tag = tagns(m.tag)
				if tag == "ProviderFault":
					self.provider_fault = ProviderFault(m)
		fault_list = []
		fault_list.append(f"detail='{self.detail}', code='{self.code}'" +
			f", machine='{self.machine}' ")
		if self.provider_fault is not None:
			fault_list.append(str(self.provider_fault))
		if isinstance(self.message, str):
			fault_list.append(self.message)
		super().__init__("\n".join(fault_list))

