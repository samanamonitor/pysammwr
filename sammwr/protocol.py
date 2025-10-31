from winrm.protocol import Protocol
from winrm.exceptions import WinRMTransportError, WinRMOperationTimeoutError
from base64 import b64encode, b64decode
import xml.etree.ElementTree as ET
from time import time
import xmltodict
import uuid
import os
import io
from .utils import tagns, get_xml_namespaces

import logging

log = logging.getLogger(__name__)

override = lambda x, y: y if x is None else x

class SoapFault(Exception):
    ns={'s': 'http://www.w3.org/2003/05/soap-envelope'}
    def __init__(self, fault_element, root=None, response_text=""):
        self.root = root
        self.response_text = response_text
        self.namespaces = get_xml_namespaces(response_text)
        if not isinstance(fault_element, ET.Element):
            raise TypeError

        if fault_element.tag != f"{{{self.ns['s']}}}Fault":
            raise TypeError(fault_element.tag)

        code=fault_element.find("s:Code/s:Value", self.ns)
        if code is not None:
            self.code = code.text

        subcode = fault_element.find("s:Code/s:Subcode", self.ns)
        self.subcode = None
        if subcode is not None:
            self.subcode = self._process_subcode(subcode)

        self.reason = fault_element.find("s:Reason/s:Text", self.ns)
        if self.reason is not None:
            self.reason = self.reason.text

        detail = fault_element.find("s:Detail", self.ns)
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
        value = element.find("s:Value", self.ns)
        if value is not None:
            out['value'] = value.text
        subcode = element.find("s:Subcode", self.ns)
        if subcode is not None:
            out['subcode'] = self.process_subcode(subcode)
        return out

class WRProtocol(Protocol):
    xmlns = {
        'a': "http://schemas.xmlsoap.org/ws/2004/08/addressing",
        's': "http://www.w3.org/2003/05/soap-envelope",
        'w': "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd",
        'rsp': "http://schemas.microsoft.com/wbem/wsman/1/windows/shell",
        'p': "http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd",
        'wsen': "http://schemas.xmlsoap.org/ws/2004/09/enumeration",
        'wf': "http://schemas.microsoft.com/wbem/wsman/1/wsmanfault",
        'wsmv': 'http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd',
        'sh': 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell',
        'xsi': "http://www.w3.org/2001/XMLSchema-instance",
        'cb': "http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd",
        'wmie': "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/MSFT_WmiError",
        'cim': "http://schemas.dmtf.org/wbem/wscim/1/common"
    }
    max_retries = 1
    def __init__(
            self, endpoint=None, transport='ntlm', username=None,
            password=None, realm=None, service="HTTP", keytab=None,
            ca_trust_path='legacy_requests', cert_pem=None, cert_key_pem=None,
            server_cert_validation='validate',
            kerberos_delegation=False,
            read_timeout_sec=Protocol.DEFAULT_READ_TIMEOUT_SEC,
            operation_timeout_sec=Protocol.DEFAULT_OPERATION_TIMEOUT_SEC,
            kerberos_hostname_override=None,
            message_encryption='auto',
            credssp_disable_tlsv1_2=False,
            send_cbt=True,
            proxy='legacy_requests'):
        username=override(username, os.environ.get('WINRM_USER', None))
        password=override(password, os.environ.get('WINRM_PASSWORD', None))
        endpoint=override(endpoint, os.environ.get('WINRM_ENDPOINT', None))
        if endpoint is None:
            raise TypeError("Endpoint not defined.")
        super(WRProtocol, self).__init__(endpoint=endpoint, transport=transport, username=username,
            password=password, realm=realm, service=service, keytab=keytab,
            ca_trust_path=ca_trust_path, cert_pem=cert_pem, cert_key_pem=cert_key_pem,
            server_cert_validation=server_cert_validation, 
            kerberos_delegation=kerberos_delegation,
            read_timeout_sec=read_timeout_sec,
            operation_timeout_sec=operation_timeout_sec,
            kerberos_hostname_override=kerberos_hostname_override,
            message_encryption=message_encryption,
            credssp_disable_tlsv1_2=credssp_disable_tlsv1_2,
            send_cbt=send_cbt)


    def send_message(self, message):
        # TODO add message_id vs relates_to checking
        # TODO port error handling code
        retries = 0
        while True:
            try:
                log.debug("Request: " + message)
                resp = self.transport.send_message(message)
                log.debug("Response: " + resp.decode('utf-8'))
                break
            except WinRMTransportError as ex:
                if ex.response_text == '' and int(ex.code) == 400:
                    if retries < self.max_retries:
                        # We need to retry because after about 5 minutes, we get a 400 without text response.
                        # this is because the authentication information is stale and we need to setup
                        # encryption with new authentication data
                        self.transport.build_session()
                        retries += 1
                    else:
                        raise
                else:
                    try:
                        # if response is XML-parseable, it's probably a SOAP fault; extract the details
                        root = ET.fromstring(ex.response_text)
                        fault = root.find('s:Body/s:Fault', self.xmlns)
                        if fault is not None:
                            raise SoapFault(fault, root=root, response_text=ex.response_text)
                        else:
                            raise
                    except Exception:
                        # assume some other transport error; raise the original exception
                        raise
        return resp

    def release(self, resource_uri, enumeration_ctx):
        req = {
            'env:Envelope': self._get_soap_header(
            resource_uri=resource_uri,  # NOQA
            action='http://schemas.xmlsoap.org/ws/2004/09/enumeration/Release')}
        req['env:Envelope'].setdefault('env:Body', {}).setdefault(
            'n:Release', {
                'n:EnumerationContext': enumeration_ctx
            })
        res=self.send_message(xmltodict.unparse(req))
        return res


    def pull(self, resource_uri, enumeration_ctx, max_elements=10, selector=None):
        req = {
            'env:Envelope': self._get_soap_header(
            resource_uri=resource_uri,  # NOQA
            action='http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull')}
        req['env:Envelope'].setdefault('env:Body', {}).setdefault(
            'n:Pull', {
                'n:EnumerationContext': enumeration_ctx,
                'n:MaxElements': max_elements
            })
        if selector is not None:
            req['env:Envelope']['env:Header']['w:SelectorSet'] = {
                'w:Selector': selector
            }
        res=self.send_message(xmltodict.unparse(req))
        return res

    def enumerate(self, resource_uri, optimize=False, max_elements=10, en_filter=None, wql=None, selector=None):
        req = {
            'env:Envelope': self._get_soap_header(
            resource_uri=resource_uri,  # NOQA
            action='http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate')}
        enum_options={}
        if optimize:
            enum_options = {
                "w:OptimizeEnumeration": {},
                "w:MaxElements": { "#text": str(max_elements) }
            }
        req['env:Envelope'].setdefault('env:Body', {}).setdefault('n:Enumerate', enum_options)

        if selector is not None:
            req['env:Envelope']['env:Header']['w:SelectorSet'] = {
                'w:Selector': selector
            }
        if wql is not None:
            req['env:Envelope']['env:Body']['n:Enumerate']['w:Filter'] = {
                '@Dialect': 'http://schemas.microsoft.com/wbem/wsman/1/WQL',
                '#text': wql
            }

        elif en_filter is not None:
            req['env:Envelope']['env:Body']['n:Enumerate']['w:Filter'] = {
                '@Dialect': 'http://schemas.dmtf.org/wbem/wsman/1/wsman/SelectorFilter',
                'w:SelectorSet': { 
                    'w:Selector': [ { '@Name': k, '#text': en_filter[k]} for k in en_filter ] }
                }
        res=self.send_message(xmltodict.unparse(req))

    def execute_method(self, namespace, resource_uri, method_name, **kwargs):
        message_id = uuid.uuid4()
        req = {
            'env:Envelope': self._get_soap_header(
                resource_uri=resource_uri,
                action='%s/%s' % (resource_uri, method_name))}
        req['env:Envelope']['env:Header']['w:SelectorSet'] = {
            'w:Selector': [{
                '@Name': '__cimnamespace',
                '#text': namespace,
            }]
        }
        body = req['env:Envelope'].setdefault('env:Body', {})
        parameters = body.setdefault('p:%s_INPUT' % method_name, {})
        _ = parameters.setdefault('@xmlns:p', resource_uri)
        for k, v in kwargs.items():
            if isinstance(v, list):
                param = parameters.setdefault(f'p:{k}', [])
                for i in v:
                    if hasattr(i, 'dict'):
                        param.append(i.dict())
                    else:
                        param.append(str(i))
            elif hasattr(v, 'dict'):
                _ = parameters.setdefault(f'p:{k}', v.dict())
            else:
                _ = parameters.setdefault(f'p:{k}', str(v))
        res = self.send_message(xmltodict.unparse(req))
        return res

    def get(self, resource_uri, selector=None, option=None):
        message_id = uuid.uuid4()
        req = {
            'env:Envelope': self._get_soap_header(
            resource_uri=resource_uri,  # NOQA
            action='http://schemas.xmlsoap.org/ws/2004/09/transfer/Get')}
        if selector is not None:
            #{
            #    'w:Selector': { '@Name': 'ShellId', '#text': '1'}
            #    }
            req['env:Envelope']['env:Header']['w:SelectorSet'] = {
                'w:Selector': selector
            }
        if option is not None:
            req['env:Envelope']['env:Header']['w:OptionSet'] = {
                'w:Option': option
            }
        req['env:Envelope'].setdefault('env:Body', {})

        res=self.send_message(xmltodict.unparse(req))
        return res

    def delete(self, resource_uri, selector=None, option=None):
        message_id = uuid.uuid4()
        req = {
            'env:Envelope': self._get_soap_header(
            resource_uri=resource_uri,  # NOQA
            action='http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete')}
        if selector is not None:
            #{
            #    'w:Selector': { '@Name': 'ShellId', '#text': '1'}
            #    }
            req['env:Envelope']['env:Header']['w:SelectorSet'] = {
                'w:Selector': selector
            }
        if option is not None:
            req['env:Envelope']['env:Header']['w:OptionSet'] = {
                'w:Option': option
            }
        req['env:Envelope'].setdefault('env:Body', {})

        res=self.send_message(xmltodict.unparse(req))
        return res

    def signal(self, shell_id, command_id, s):
        message_id = uuid.uuid4()
        req = {'env:Envelope': self._get_soap_header(
            resource_uri='http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd',  # NOQA
            action='http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal',  # NOQA
            shell_id=shell_id,
            message_id=message_id)}

        # Signal the Command references to terminate (close stdout/stderr)
        signal = req['env:Envelope'].setdefault(
            'env:Body', {}).setdefault('rsp:Signal', {})
        signal['@CommandId'] = command_id
        signal['rsp:Code'] = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/%s' % s  # NOQA

        res = self.send_message(xmltodict.unparse(req))        
        return res

    def send(self, shell_id, command_id, stdin_input, end=False):
        req = {'env:Envelope': self._get_soap_header(
                    resource_uri='http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd',  # NOQA
                    action='http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send',  # NOQA
                    shell_id=shell_id)}
        stdin_envelope = req['env:Envelope'].setdefault('env:Body', {}).setdefault(
                    'rsp:Send', {}).setdefault('rsp:Stream', {})
        stdin_envelope['@CommandId'] = command_id
        stdin_envelope['@Name'] = 'stdin'
        stdin_envelope['@End'] = str(end)
        stdin_envelope['@xmlns:rsp'] = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell'
        stdin_envelope['#text'] = b64encode(stdin_input)
        start_time = time()
        res = self.send_message(xmltodict.unparse(req))
        total_time = time() - start_time
        return (res, total_time)

    def receive(self, shell_id, command_id):
        req = {'env:Envelope': self._get_soap_header(
                    resource_uri='http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd',  # NOQA
                    action='http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive',  # NOQA
                    shell_id=shell_id)}
        stream = req['env:Envelope'].setdefault('env:Body', {}).setdefault(
            'rsp:Receive', {}).setdefault('rsp:DesiredStream', {})
        stream['@CommandId'] = command_id
        stream['#text'] = 'stdout stderr'
        start_time = time()
        res = self.send_message(xmltodict.unparse(req))
        total_time = time() - start_time
        root = ET.fromstring(res)

        stdout = stderr = b''
        stream_stdout = root.findall('.//rsp:Stream[@Name=\'stdout\']', self.xmlns)
        for stream_node in stream_stdout:
            if stream_node.text is not None:
                stdout += b64decode(stream_node.text.encode('ascii'))
        stream_stderr = root.findall('.//rsp:Stream[@Name=\'stderr\']', self.xmlns)
        for stream_node in stream_stderr:
            if stream_node.text is not None:
                stderr += b64decode(stream_node.text.encode('ascii'))

        cs=root.find('.//rsp:CommandState[@State=\'%(rsp)s/CommandState/Done\']' % self.xmlns, self.xmlns)
        command_done = cs is not None
        ec=root.find('.//rsp:ExitCode', self.xmlns)
        if ec is not None:
            return_code = int(ec.text)
        else:
            return_code = -1
        return stdout, stderr, return_code, command_done, total_time

    def close_session(self):
        if not self.transport.session:
            return
        self.transport.session.close()
        self.transport.session = None
