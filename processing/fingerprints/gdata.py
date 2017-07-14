from mitmengine.ciphers import Ciphers
from fingerprint import Fingerprint


class GData(Fingerprint):

    TYPE = "antivirus"
    VERSION = Fingerprint.VERSION_TLS_1_2
    CIPHERS = [
        Ciphers.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
        Ciphers.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
        Ciphers.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
        Ciphers.TLS_ECDH_Anon_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_DH_Anon_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_DH_Anon_WITH_AES_256_CBC_SHA256,
        Ciphers.TLS_DH_Anon_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_DH_Anon_WITH_CAMELLIA_256_CBC_SHA,
        Ciphers.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
        Ciphers.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
        Ciphers.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_RSA_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_RSA_WITH_AES_256_CBC_SHA256,
        Ciphers.TLS_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
        Ciphers.TLS_ECDH_Anon_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_DH_Anon_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_DH_Anon_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_DH_Anon_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_DH_Anon_WITH_CAMELLIA_128_CBC_SHA,
        Ciphers.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_RSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_RSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_ECDH_Anon_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_DH_Anon_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    ]
    EXTENSIONS = [11, 10, 35, 13, 15]
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
    EC_POINT_FORMATS = [0,1,2]
    # doesn't check certificates. :(
    MAX_SECURITY = 4

    # as far as I can tell, this is the AV that uses anonymous ciphers

    def match(self, version, ciphers, extensions, headers,
            ec_point_formats, curves, ua, compression):
        if Ciphers.TLS_DH_Anon_WITH_3DES_EDE_CBC_SHA not in ciphers:
            return False, None
        if ec_point_formats and ec_point_formats != self.EC_POINT_FORMATS:
            return False, None
        if curves and curves != self.CURVES:
            return False, None
        return True, self.MAX_SECURITY
