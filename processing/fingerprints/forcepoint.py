from mitmengine.ciphers import Ciphers
from fingerprint import Fingerprint

class ForcePoint(Fingerprint):

    VERSION = Fingerprint.VERSION_TLS_1_2
    TYPE = "proxy"

    EXTENSIONS = [0x0000, 0x000b, 0x000a, 0x000d, 0x000f]
    CURVES = [25, 24, 23]
    EC_POINT_FORMATS = [0,1,2]

    # Accepts RC4 ciphers
    MAX_SECURITY = 3

    def match(self, version, ciphers, extensions, headers,
            ec_point_formats, curves, ua, compression):
        # nobody else uses the curve order 25, 24, 23.
        h = set(headers)
        if "Client-IP" in h and "X-Forwarded-For" in h:
            return True, self.MAX_SECURITY
        if extensions != self.EXTENSIONS:
            return False, None
        if curves == self.CURVES:
            return True, self.MAX_SECURITY
        return False, None
