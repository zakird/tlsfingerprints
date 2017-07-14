from mitmengine.ciphers import Ciphers
from fingerprint import Fingerprint

class JuniperSRXDefault(Fingerprint):

    TYPE = "proxy"

    # no perfect forward secrecy

    VERSION = None
    CIPHERS = [
        Ciphers.TLS_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_RSA_WITH_RC4_128_SHA,
        Ciphers.TLS_RSA_WITH_RC4_128_MD5,
        Ciphers.TLS_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    ]
    EXTENSIONS = [0x000, 0x000d, 0x000f]
    EC_POINT_FORMATS = []
    CURVES = []
    MAX_SECURITY = 3


class JuniperSRXStrong(Fingerprint):

    # no perfect forward secrecy
    TYPE = "proxy"
    VERSION = None
    CIPHERS = [
        Ciphers.TLS_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    ]
    EXTENSIONS = [0x000, 0x000d, 0x000f]
    EC_POINT_FORMATS = []
    CURVES = []
    MAX_SECURITY = 3


class JuniperSRXWeak(Fingerprint):

    TYPE = "proxy"
    VERSION = None
    CIPHERS = [
        Ciphers.TLS_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_RSA_WITH_RC4_128_SHA,
        Ciphers.TLS_RSA_WITH_RC4_128_MD5,
        Ciphers.TLS_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_RSA_WITH_DES_CBC_SHA,
        Ciphers.TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,
        Ciphers.TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,
        Ciphers.TLS_RSA_EXPORT1024_WITH_RC4_56_MD5,
        Ciphers.TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
        Ciphers.TLS_RSA_EXPORT_WITH_RC4_40_MD5,
        Ciphers.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
    ]
    EXTENSIONS = [0x000, 0x000d, 0x000f]
    EC_POINT_FORMATS = []
    CURVES = []

    # supports export suites
    MAX_SECURITY = 4
