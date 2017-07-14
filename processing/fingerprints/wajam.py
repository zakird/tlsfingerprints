from mitmengine.ciphers import Ciphers
from fingerprint import Fingerprint

class Wajam_97e8f6b46de9e1e3e312de78ed90e17f(Fingerprint):

    TYPE = "malware"

    # version 2.6
    # we also looked at the following, which weren't installers:
    #   84bb0f26c1a16760d2b9b3dcbc1b9088
    #   b6777b948bb2fb9d583c254f41bda789
    #   d27f95e851a23a6c2c330b6ceb71dd19
    #   d92069cb5fdf89e46d2ea96adc71d07f

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
        Ciphers.TLS_RSA_WITH_RC4_128_MD5,
    ]

    EXTENSIONS = [0x0000, 0x000a, 0x000b, 0x0023]
    CURVES = [0x0017, 0x0018]
    EC_POINT_FORMATS = [0,]
    MAX_SECURITY = 3
