from mitmengine.ciphers import Ciphers
from fingerprint import Fingerprint

class DrWeb10_2016(Fingerprint):

    TYPE = "antivirus"

    VERSION = Fingerprint.VERSION_TLS_1_2
    CIPHERS = [
        Ciphers.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_RSA_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_RSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_RSA_WITH_AES_256_CBC_SHA256,
        Ciphers.TLS_RSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
        Ciphers.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
    ]

    EXTENSIONS = [0, 10, 11, 13, 23, 0xff01]
    CURVES = [23, 24]
    EC_POINT_FORMATS = [0,]
    # accepts RC4
    MAX_SECURITY = 3


class DrWeb10_2015(Fingerprint):

    TYPE = "antivirus"

    VERSION = Fingerprint.VERSION_TLS_1_0
    CIPHERS = [
        Ciphers.TLS_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_RSA_WITH_RC4_128_SHA,
        Ciphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_RSA_WITH_RC4_128_MD5
    ]

    EXTENSIONS = [0xff01, 0, 10, 11]
    CURVES = [23, 24]
    EC_POINT_FORMATS = [0,]
    # vulnerable to BEAST and FREAK. Doesn't check revocation.
    MAX_SECURITY = 3
