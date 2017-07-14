from mitmengine.ciphers import Ciphers
from fingerprint import Fingerprint

class Chromodo(Fingerprint):

    TYPE = "fake-browser"

    # accepts all sized diffie-hellman parameters
    MAX_SECURITY = 4

    def match(self, version, ciphers, extensions, headers,
            ec_point_formats, curves, ua, compression):
        if ua and "Dragon/" in ua:
            return True, self.MAX_SECURITY
        return False, None

