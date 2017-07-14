from mitmengine.ciphers import Ciphers
from fingerprint import Fingerprint

class BlueCoat(Fingerprint):

    TYPE = "proxy"

    def match(self, version, ciphers, extensions, headers,
            ec_point_formats, curves, ua, compression):
        for header in headers:
            if "bluecoat" in header.lower():
                return True, self.MAX_SECURITY
        else:
            return False, None


class BlueCoatFingerprint(Fingerprint):
    # Blue Coat copies ciphers, identify via unique extensions + curves
    TYPE = "proxy"

    VERSION = Fingerprint.VERSION_TLS_1_2

    EXTENSIONS = [0, 11, 10, 13]
    CURVES = [14, 13, 25, 11, 12, 24, 9, 10, 22, 23, 8, 6, 7, 20, 21, 4, 5, 18, 19, 1, 2, 3, 15, 16, 17]
    EC_POINT_FORMATS = [0,1,2]

    def match(self, version, ciphers, extensions, headers,
            ec_point_formats, curves, ua, compression):
        if not (version and ciphers and extensions and curves and ec_point_formats):
            return False, None
        if version != self.VERSION:
            return False, None
        if ciphers[-1] != Ciphers.TLS_EMPTY_RENEGOTIATION_INFO_SCSV:
            return False, None
        if extensions != self.EXTENSIONS:
            return False, None
        if ec_point_formats != self.EC_POINT_FORMATS:
            return False, None
        if curves != self.CURVES:
            return False, None

        return True, None


#class BlueCoatNoAgent(Fingerprint):
#
#    TYPE = "proxy"
#
#    def match(self, version, ciphers, extensions, headers,
#            ec_point_formats, curves, ua, compression):
#        if ua == "Mozilla/4.0 (compatible;)":
#            return True, self.MAX_SECURITY
#        return False, self.MAX_SECURITY
