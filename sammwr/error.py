import xml.etree.ElementTree as ET
from .utils import tagns

class WRError(Exception):
    def __init__(self, *args):
        if len(args) > 1:
            self.root = ET.fromstring(args[1])
        super().__init__(self.args[0])
    code = 500
    @property
    def response_text(self):
        return self.args[1]

    @property
    def fault_data(self):
        return self.args[2]
    
    @property
    def fault_detail(self):
        return self.args[3]

class SoapFault(Exception):
    ns='http://www.w3.org/2003/05/soap-envelope'
    def __init__(self, fault_element, root=None, response_text=""):
        self.root = root
        self.response_text = response_text
        if not isinstance(fault_element, ET.Element):
            raise TypeError("fault_element", fault_element)
        if fault_element.tag != f"{{{self.ns}}}Fault":
            raise TypeError(f"Expecting tag '{{{self.ns}}}Fault'. Received {fault_element.tag}")
        code=fault_element.find("{*}Code/{*}Value")
        if code is not None:
            self.code = code.text
        subcode = fault_element.find("{*}Code/{*}Subcode")
        self.subcode = None
        if subcode is not None:
            self.subcode = self._process_subcode(subcode)
        self.reason = fault_element.find("{*}Reason/{*}Text")
        if self.reason is not None:
            self.reason = self.reason.text
        detail = fault_element.find("{*}Detail")
        detail_str = ""
        self.fault_detail = ""
        self.detail_type = "text"
        if len(detail) == 0:
            self.detail = detail.text
            detail_str = self.detail
        else:
            self.detail = detail
            detail_types = []
            for d in self.detail:
                if "FaultDetail" in d.tag:
                    self.fault_detail = d.text
                    continue
                (_, tag) = tagns(d.tag)
                detail_types.append(tag)
            detail_str = ",".join(detail_types)
        super().__init__(f"SoapFault: code: {self.code}, subcode: {self.subcode} reason: '{self.reason}' fault_detail: '{self.fault_detail}' detail: '{detail_str}'")

    def _process_subcode(self, element):
        out = {}
        value = element.find("{*}Value")
        if value is not None:
            out['value'] = value.text
        subcode = element.find("{*}Subcode")
        if subcode is not None:
            out['subcode'] = self.process_subcode(subcode)
        return out

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsman/0d0e65bf-e458-4047-8065-b401dae2023e
class WsManFault(Exception):
    def __init__(self, soap_fault):
        if not isinstance(soap_fault, SoapFault):
            raise TypeError("Expecting type SoapFault")
        self.soap_fault = soap_fault
        wmf_detail = soap_fault.detail.find(".//{*}WSManFault")
        if wmf_detail is None:
            raise TypeError("SoapFault doesn't contain a WSManFault")
        self.detail = wmf_detail.text
        self.code = wmf_detail.attrib.get('Code')
        self.machine = wmf_detail.attrib.get('Machine')
        self.message = wmf_detail.find('{*}Message')
        self.provider_fault = None
        if len(self.message) == 0:
            self.message = self.message.text
        else:
            for m in self.message:
                _, tag = tagns(m.tag)
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
                        self.provider_fault = WsManFault(wsmf, soap_fault)
        fault_list = []
        fault_list.append(f"WsManFault: detail='{self.detail}', code='{self.code}'" + 
            f", machine='{self.machine}' ")
        if self.provider_fault is not None:
            fault_list.append(f"   Provider: id='{self.provider_id}', " +
                f"provider='{self.provider}', path='{self.path}'")
        if self.provider_fault is not None:
            fault_list.append(f"      Inner Fault: {str(self.provider_fault)}")
        if isinstance(self.message, str):
            fault_list.append(self.message)
        super().__init__("\n".join(fault_list))
