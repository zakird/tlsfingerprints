from mitmengine.ciphers import Ciphers
from fingerprint import Fingerprint

class PCPandora(Fingerprint):

    TYPE = "antivirus"
    VERSION = Fingerprint.VERSION_TLS_1_2
    CIPHERS = [
        Ciphers.TLS_RSA_WITH_RC4_128_MD5,
        Ciphers.TLS_RSA_WITH_RC4_128_SHA,
        Ciphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA
    ]
    EXTENSIONS = [0, 23, 35, 13, 18, 16, 0x7550]
    EC_POINT_FORMATS = []
    CURVES = []
    # accepts all certificates
    MAX_SECURITY = 4

class PCPandora7_0_22(Fingerprint):
    TYPE = "antivirus"
    VERSION = Fingerprint.VERSION_TLS_1_0
    CIPHERS = [
        Ciphers.TLS_RSA_WITH_RC4_128_MD5,
        Ciphers.TLS_RSA_WITH_RC4_128_SHA,
        Ciphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA
    ]
    EXTENSIONS = [0]
    EC_POINT_FORMATS = []
    CURVES = []
    # accepts all certificates
    MAX_SECURITY = 4
