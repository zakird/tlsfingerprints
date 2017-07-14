from mitmengine.ciphers import Ciphers
from fingerprint import Fingerprint

class AdGuard(Fingerprint):

    TYPE = "antivirus"

    VERSION = Fingerprint.VERSION_TLS_1_2
    CIPHERS = [
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_RSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_RSA_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_RENEGO_PROTECTION_REQUEST,
    ]

    EXTENSIONS = [0, 11, 10, 35, 13, 5, 15]
    CURVES = [23, 25, 28, 27, 24, 26, 22, 14, 13, 11, 12, 9, 10]
    EC_POINT_FORMATS = [0, 1, 2]

    MAX_SECURITY = 2
