from mitmengine.ciphers import Ciphers
from fingerprint import Fingerprint

class MicrosoftTMG(Fingerprint):

    TYPE = "proxy"

    # this accepts SSLv2...
    MAX_SECURITY = 4

    def match(self, version, ciphers, extensions, headers,
            ec_point_formats, curves, ua, compression):
        if version == self.VERSION_SSL_2:
            return True, self.MAX_SECURITY
        return False, None
