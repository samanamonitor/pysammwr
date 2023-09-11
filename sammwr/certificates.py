from sammwr.registry import HKEY_LOCAL_MACHINE, CIM_RegistryKey
from sammwr.utils import CertBlob
import re
from datetime import datetime

class WRCertificates:
	def __init__(self, *args, **kwargs):
		self.path='SOFTWARE\\Microsoft\\SystemCertificates\\MY\\Certificates'
		self.cert_keys=CIM_RegistryKey(HKEY_LOCAL_MACHINE, self.path, **kwargs)

	def __iter__(self):
		self._iter = iter(self.cert_keys.children)
		return self

	def __next__(self):
		cert = next(self._iter)
		cb = CertBlob(cert.getvalue('Blob').value)
		days_to_expire = (cb.certificate.not_valid_after - datetime.now()).days
		try:
			friendly_name = cb.friendly_name
		except AttributeError:
			friendly_name = re.findall(r'CN=.*', cb.certificate.subject.rfc4514_string())[0]
		return {
			'sslcertkeyname': friendly_name,
			'ssldaystoexpire': days_to_expire
		}