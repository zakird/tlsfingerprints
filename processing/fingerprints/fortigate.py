from mitmengine.ciphers import Ciphers
from fingerprint import Fingerprint

class Fortigate(Fingerprint):

    # accepts all sized diffie-hellman parameters (logjam)
    # vulnerable to POODLE
    MAX_SECURITY = 3
    TYPE = "proxy"

    def match(self, version, ciphers, extensions, headers,
            ec_point_formats, curves, ua, compression):
        if extensions == [0x000a, 0x000b, 0x0000, 0x000d, 0x0017] or \
                extensions == [0x000a, 0x000b, 0x0000, 0x000d]:
            return True, self.MAX_SECURITY
        return False, None
