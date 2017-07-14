from mitmengine.ciphers import Ciphers
from fingerprint import Fingerprint

class BullGuard(Fingerprint):

    TYPE = "antivirus"

    VERSION = Fingerprint.VERSION_TLS_1_0
    CIPHERS = [
        Ciphers.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
        Ciphers.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_SEED_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_SEED_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
        Ciphers.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_RSA_WITH_SEED_CBC_SHA,
        Ciphers.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
        Ciphers.TLS_RSA_WITH_IDEA_CBC_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
        Ciphers.TLS_ECDH_RSA_WITH_RC4_128_SHA,
        Ciphers.TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
        Ciphers.TLS_RSA_WITH_RC4_128_SHA,
        Ciphers.TLS_RSA_WITH_RC4_128_MD5,
        Ciphers.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_DES_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_DES_CBC_SHA,
        Ciphers.TLS_RSA_WITH_DES_CBC_SHA,
        Ciphers.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
    ]

    EXTENSIONS = [0, 11, 10, 35, 15]
    EC_POINT_FORMATS = [0,1,2]
    CURVES = [
        0x000e,
        0x000d,
        0x0019,
        0x000b,
        0x000c,
        0x0018,
        0x0009,
        0x000a,
        0x0016,
        0x0017,
        0x0008,
        0x0006,
        0x0007,
        0x0014,
        0x0015,
        0x0004,
        0x0005,
        0x0012,
        0x0013,
        0x0001,
        0x0002,
        0x0003,
        0x000f,
        0x0010,
        0x0011,
    ]
    # vulnerable to BEAST and Logjam
    # accepted invalid CA certificates in NDSS
    MAX_SECURITY = 4


class BullGuard16_0_314_4(Fingerprint):
    #copies ciphers
    EXTENSIONS = [0, 11, 10, 35, 13, 15]
    CURVES = [
        0x0017,
        0x0019,
        0x001c,
        0x001b,
        0x0018,
        0x001a,
        0x0016,
        0x000e,
        0x000d,
        0x000b,
        0x000c,
        0x0009,
        0x000a
    ]

    MAX_SECURITY = 3 # POODLE

    # this seems to match ciphers, but not curves, signature algorithms, or
    # elliptic curves
    def match(self, version, ciphers, extensions, headers,
            ec_point_formats, curves, ua, compression):
        return False, None
        if ciphers[-1] != Ciphers.TLS_EMPTY_RENEGOTIATION_INFO_SCSV:
            return False, None
        if curves and curves != self.CURVES:
            return False, None
        if ec_point_formats and ec_point_formats != [0,1,2]:
            return False, None
        return True, self.MAX_SECURITY
