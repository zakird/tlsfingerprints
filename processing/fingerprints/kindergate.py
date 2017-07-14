from mitmengine.ciphers import Ciphers
from fingerprint import Fingerprint

class Kindergate(Fingerprint):

    TYPE = "parental"
    VERSION = Fingerprint.VERSION_TLS_1_2

    CIPHERS = [
        Ciphers.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
        Ciphers.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_RSA_WITH_RC4_128_SHA,
        Ciphers.TLS_RSA_WITH_RC4_128_MD5,
        Ciphers.TLS_DHE_RSA_WITH_DES_CBC_SHA,
        Ciphers.TLS_RSA_WITH_DES_CBC_SHA,
    ]
    EXTENSIONS = []
    CURVES = []
    EC_POINT_FORMATS = []
    # checks no certificates
    MAX_SECURITY = 4
