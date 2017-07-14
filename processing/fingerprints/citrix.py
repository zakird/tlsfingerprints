from mitmengine.ciphers import Ciphers
from fingerprint import Fingerprint

class Citrix(Fingerprint):

    TYPE = "proxy"

    def match(self, version, ciphers, extensions, headers,
            ec_point_formats, curves, ua, compression):
        for header in headers:
            if header.lower() == "Pxyro-Connection":
                return True, self.MAX_SECURITY
        else:
            return False, None
