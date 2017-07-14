from mitmengine.ciphers import Ciphers
from fingerprint import Fingerprint

class Avast(Fingerprint):

    TYPE = "antivirus"

    VERSION = Fingerprint.VERSION_TLS_1_2

    CIPHERS = [
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_RSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    ]

    EXTENSIONS = [0, 11, 10, 35, 13, 5, 15, 13172, 16, 99]
    CURVES = [23, 24]
    EC_POINT_FORMATS = [0,1,2]

     MAX_SECURITY = 1


class AvastMac(Fingerprint):

    TYPE = "antivirus"

    VERSION = Fingerprint.VERSION_TLS_1_2
    MAX_SECURITY = 3 # RC4 and single DES

    CIPHERS = [
        Ciphers.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_DH_DSS_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_DH_RSA_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
        Ciphers.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
        Ciphers.TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
        Ciphers.TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
        Ciphers.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_DH_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_DH_DSS_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
        Ciphers.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA,
        Ciphers.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA,
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
        Ciphers.TLS_DH_DSS_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_DH_RSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_DH_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_DH_DSS_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_SEED_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_SEED_CBC_SHA,
        Ciphers.TLS_DH_RSA_WITH_SEED_CBC_SHA,
        Ciphers.TLS_DH_DSS_WITH_SEED_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
        Ciphers.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA,
        Ciphers.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA,
        Ciphers.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_RSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_RSA_WITH_AES_128_CBC_SHA256,
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
        Ciphers.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_DHE_RSA_WITH_DES_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_DES_CBC_SHA,
        Ciphers.TLS_DH_RSA_WITH_DES_CBC_SHA,
        Ciphers.TLS_DH_DSS_WITH_DES_CBC_SHA,
        Ciphers.TLS_RSA_WITH_DES_CBC_SHA,
        Ciphers.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    ]

    EXTENSIONS = [0, 11, 10, 35, 13, 15, 21]
    CURVES = [23, 25, 28, 27, 24, 26, 22, 14, 13, 11, 12, 9, 10]
    EC_POINT_FORMATS = [0,1,2]


class AvastBroader(Fingerprint):

    TYPE = "antivirus"

    VERSION = Fingerprint.VERSION_TLS_1_2

    POSSIBLE_EXTENSION_SETS = [
        [0, 11, 10, 35, 13, 5, 15, 13172, 16],
        [0, 11, 10, 35, 13, 5, 15, 16],
        [0x000, 0x000b, 0x000a, 0x0023, 0x000d, 0x000f]
    ]

    # Copies ciphers from browsers, but not extensions
    # offers NPN which other browsers no longer offer
    def match(self, version, ciphers, extensions, headers,
            ec_point_formats, curves, ua, compression):
        if extensions not in self.POSSIBLE_EXTENSION_SETS:
            return False, None
        if curves and curves != [23, 24]:
            return False, None
        if ciphers[-1] != Ciphers.TLS_EMPTY_RENEGOTIATION_INFO_SCSV:
            return False, None
        if ec_point_formats and ec_point_formats != [0,1,2]:
            return False, None
        return True, self.MAX_SECURITY

    MAX_SECURITY = 1
