from mitmengine.ciphers import Ciphers
from fingerprint import Fingerprint

class Untangle_11_2_1(Fingerprint):

    TYPE = "proxy"

    MAX_SECURITY = 3

    CIPHERS = [
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
        Ciphers.TLS_RSA_WITH_RC4_128_SHA,
        Ciphers.TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
        Ciphers.TLS_ECDH_RSA_WITH_RC4_128_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_RSA_WITH_RC4_128_MD5,
        Ciphers.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
    ]

    CURVES = [
        0x0017,
        0x0001,
        0x0003,
        0x0013,
        0x0015,
        0x0006,
        0x0007,
        0x0009,
        0x000a,
        0x0018,
        0x000b,
        0x000c,
        0x0019,
        0x000d,
        0x000e,
        0x000f,
        0x0010,
        0x0011,
        0x0002,
        0x0012,
        0x0004,
        0x0005,
        0x0014,
        0x0008,
        0x0016,
    ]

    EXTENSIONS = [
        0x000a,
        0x000b
    ]


class Untangle_12_0_0(Fingerprint):

    MAX_SECURITY = 3
    TYPE = "proxy"

    CIPHERS = [
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_RSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
        Ciphers.TLS_RSA_WITH_RC4_128_SHA,
        Ciphers.TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
        Ciphers.TLS_ECDH_RSA_WITH_RC4_128_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_RSA_WITH_RC4_128_MD5,
        Ciphers.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
    ]

    EXTENSIONS = [
        0x000a,
        0x000b,
        0x000d,
        0x0000
    ]

    CURVES = [
        0x0017,
        0x0001,
        0x0003,
        0x0013,
        0x0015,
        0x0006,
        0x0007,
        0x0009,
        0x000a,
        0x0018,
        0x000b,
        0x000c,
        0x0019,
        0x000d,
        0x000e,
        0x000f,
        0x0010,
        0x0011,
        0x0002,
        0x0012,
        0x0004,
        0x0005,
        0x0014,
        0x0008,
        0x0016,
   ]
