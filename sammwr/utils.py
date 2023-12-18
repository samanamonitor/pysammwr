import struct
import binascii
from cryptography import x509

def cert_key_prov_info(s):
    offset_to_container_name, offset_to_provider_name, provider_type, \
        flags, _, _, key_specification = struct.unpack("iiiiiii", s[:7*4])
    container_name = s[offset_to_container_name:offset_to_provider_name].decode('utf-16').strip('\0')
    provider_name = s[offset_to_provider_name:].decode('utf-16').strip('\0')
    return (provider_type, flags, key_specification, provider_name, container_name)


class CertBlob:
    '''Certificate info taken from:
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpef/e051aba9-c9df-4f82-a42a-c13012c9d381
    '''
    PropertyTransform = {
        2: lambda x: cert_key_prov_info(x),
        3: lambda x: binascii.hexlify(x).upper(),
        4: lambda x: binascii.hexlify(x).upper(),
        6: lambda x: int(x),
        9: lambda x: x,
        11: lambda x: x.decode('utf-16').strip('\0'),
        13: lambda x: x.decode('utf-16').strip('\0'),
        15: lambda x: binascii.hexlify(x).upper(),
        19: lambda x: True,
        20: lambda x: binascii.hexlify(x).upper(),
        21: lambda x: x.decode('utf-16').strip('\0'),
        22: lambda x: x,
        24: lambda x: binascii.hexlify(x).upper(),
        25: lambda x: binascii.hexlify(x).upper(),
        24: lambda x: binascii.hexlify(x).upper(),
        27: lambda x: x,
        28: lambda x: binascii.hexlify(x).upper(),
        29: lambda x: binascii.hexlify(x).upper(),
        32: lambda x: x509.load_der_x509_certificate(x),
        71: lambda x: x.decode('utf-16').strip('\0'),
        87: lambda x: struct.unpack("iiiii", x[:20]) + (x[20:].decode('utf-16').split('\0'),),
        89: lambda x: x.decode('utf-16').strip('\0')
    }
    PropertyName = {
        2: 'key_prov_info',
        3: 'sha1_hash',
        4: 'md5_hash',
        6: 'key_spec',
        9: 'enhkey_usage',
        11: 'friendly_name',
        13: 'description',
        15: 'signature_hash',
        19: 'disabled',
        20: 'key_identifier',
        21: 'auto_enroll',
        22: 'pubkey_alg_para',
        24: 'issuer_public_key_md5_hash',
        25: 'subject_public_key_md5_hash',
        27: 'date_stamp',
        28: 'issuer_serial_number_md5_hash',
        29: 'subject_name_md5_hash',
        32: 'certificate'
    }

    def __init__(self, s):
        if not isinstance(s, bytes):
            raise TypeError("Invalid input type. Must be 'bytes'.")

        self.cert_data={}
        while len(s):
            PropertyID, _, Length = struct.unpack("iii", s[:12])
            Value = self.PropertyTransform.get(PropertyID, lambda x:x)(s[12:12+Length])
            _ = self.cert_data.setdefault(self.PropertyName.get(PropertyID, PropertyID), Value)
            s = s[12+Length:]

    def has_property(self, key):
        return key in self.cert_data

    def __getattr__(self, key):
        if key not in self.cert_data:
            raise AttributeError("Attribute %s not defined" % key)
        return self.cert_data.get(key, None)


def hexdump(binstring):
   for pos in range(len(binstring)):
      if pos % 16 == 0:
         print('')
         print('%04x   ' % pos, end='')
      elif pos % 8 == 0:
         print('   ', end='')
      print("%02x " % binstring[pos], end='')
   print('')

