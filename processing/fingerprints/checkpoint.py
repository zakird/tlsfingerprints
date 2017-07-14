from mitmengine.ciphers import Ciphers
from fingerprint import Fingerprint

class Checkpoint(Fingerprint):

    TYPE = "proxy"

    VERSION = Fingerprint.VERSION_TLS_1_0

    CIPHERS = [
        Ciphers.TLS_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_RSA_WITH_RC4_128_SHA,
        Ciphers.TLS_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_RSA_WITH_RC4_128_MD5,
        Ciphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        0x01ff
    ]

    EXTENSIONS = [0,]

    # does not check certificate expiration
    MAX_SECURITY = 4
