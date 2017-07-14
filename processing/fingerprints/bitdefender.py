from mitmengine.ciphers import Ciphers
from fingerprint import Fingerprint

class BitDefender(Fingerprint):

    TYPE = "antivirus"

    VERSION = Fingerprint.VERSION_TLS_1_2

    CIPHERS = [
        Ciphers.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
        Ciphers.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
        Ciphers.TLS_RSA_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_RSA_WITH_AES_256_CBC_SHA256,
        Ciphers.TLS_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
        Ciphers.TLS_RSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_RSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        Ciphers.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        Ciphers.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_RSA_WITH_RC4_128_MD5,
        Ciphers.TLS_RSA_WITH_RC4_128_SHA,
        Ciphers.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
    ]

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
    EXTENSIONS = [0, 11, 10, 35, 13, 15]
    EC_POINT_FORMATS = [0,1,2]
    # vulnerable to the BEAST attack
    MAX_SECURITY = 3


class BitDefender20150204(Fingerprint):

    TYPE = "antivirus"
    VERSION = Fingerprint.VERSION_TLS_1_2
    CIPHERS = [
        Ciphers.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
        Ciphers.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
        Ciphers.TLS_RSA_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_RSA_WITH_AES_256_CBC_SHA256,
        Ciphers.TLS_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
        Ciphers.TLS_RSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_RSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        Ciphers.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        Ciphers.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_RSA_WITH_RC4_128_MD5,
        Ciphers.TLS_RSA_WITH_RC4_128_SHA,
        Ciphers.TLS_RENEGO_PROTECTION_REQUEST
    ]

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
        0x0011
    ]
    EXTENSIONS = [0x0000, 0x000b, 0x000a, 0x0023, 0x000d, 0x000f, 0x0015]
    EC_POINT_FORMATS = [0,1,2]
    # vulnerable to the BEAST attack
    MAX_SECURITY = 3
