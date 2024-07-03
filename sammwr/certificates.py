from sammwr.registry import HKEY_LOCAL_MACHINE, CIM_RegistryKey
from sammwr.utils import CertBlob
import re
from datetime import datetime
from cryptography.x509 import NameOID, ExtensionOID

class WRCertificates:
	def __init__(self, *args, **kwargs):
		self.path='SOFTWARE\\Microsoft\\SystemCertificates\\MY\\Certificates'
		self.cert_keys=CIM_RegistryKey(HKEY_LOCAL_MACHINE, self.path, **kwargs)

	def __iter__(self):
		self._iter = iter(self.cert_keys.children)
		return self

	def __next__(self):
		while True:
			cert = next(self._iter)
			cb = CertBlob(cert.getvalue('Blob').value)
			if not cb.has_property('disabled'):
				break
		days_to_expire = (cb.certificate.not_valid_after - datetime.now()).days

		san = cb.certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
		san_list = list(map(lambda x: x.value, san.value))
		cn = cb.certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
		cn_list = list(map(lambda x: x.value, cn.value))
		common_name = ''
		if len(cn_list) > 0:
			common_name = cn_list[0]

		if cb.has_property('friendly_name'):
			friendly_name = cb.friendly_name
		elif len(cn_list) > 0:
			friendly_name = cn_list[0]
		elif len(san_list) > 0:
			friendly_name = san_list[0]
		else:
			friendly_name = cb.sha1_hash.decode('utf-8')

		return {
			'not_valid_after': int(cb.certificate.not_valid_after.timestamp() * 1000),
			'friendly_name': friendly_name,
			'common_name': cn_list,
			'subject': cb.certificate.subject.rfc4514_string(),
			'subject_alternative_name': san_list,
			'issuer': cb.certificate.issuer.rfc4514_string(),
			'sha1_hash': cb.sha1_hash.decode('utf-8'),
			'sslcertkeyname': friendly_name,
			'ssldaystoexpire': days_to_expire
		}
