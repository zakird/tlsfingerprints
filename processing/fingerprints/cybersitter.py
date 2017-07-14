from mitmengine.ciphers import Ciphers
from fingerprint import Fingerprint

class CyberSitter(Fingerprint):

    TYPE = "parental"

    VERSION = Fingerprint.VERSION_TLS_1_2
    CIPHERS = [
        Ciphers.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
        Ciphers.TLS_ECDH_RSA_WITH_RC4_128_SHA,
        Ciphers.TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
        Ciphers.TLS_RSA_WITH_RC4_128_SHA,
        Ciphers.TLS_RSA_WITH_RC4_128_MD5,
        Ciphers.TLS_RSA_EXPORT_WITH_RC4_40_MD5,
        Ciphers.TLS_DHE_RSA_WITH_SEED_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_SEED_CBC_SHA,
        Ciphers.TLS_RSA_WITH_SEED_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_DES_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_DES_CBC_SHA,
        Ciphers.TLS_RSA_WITH_DES_CBC_SHA,
        Ciphers.TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
        Ciphers.TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
        Ciphers.TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_RSA_WITH_IDEA_CBC_SHA,
        Ciphers.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    ]
    EXTENSIONS = [0, 11, 10, 35, 13, 15]
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
    # vulnerable to BEAST and Logjam, POODLE, uses EXPORTS
    # accepts all certificates
    MAX_SECURITY = 4


class CyberSitterHeader(Fingerprint):

    TYPE = "proxy"

    # vulnerable to BEAST and Logjam, POODLE, uses EXPORTS
    # accepts all certificates
    MAX_SECURITY = 4

    def match(self, version, ciphers, extensions, headers,
            ec_point_formats, curves, ua, compression):
        for header in headers:
            if "cybersitter" in header.lower():
                return True, self.MAX_SECURITY
        else:
            return False, None
