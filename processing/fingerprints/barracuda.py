from mitmengine.ciphers import Ciphers
from fingerprint import Fingerprint

class Barracuda(Fingerprint):

    TYPE = "proxy"
    # accepts all sized diffie-hellman parameters
    MAX_SECURITY = 3

    def match(self, version, ciphers, extensions, headers,
            ec_point_formats, curves, ua, compression):
        if "CUDA_CLIIP" in headers:
            return True, self.MAX_SECURITY
        return False, None
