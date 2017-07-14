from mitmengine.ciphers import Ciphers
from fingerprint import Fingerprint

class Kaspersky(Fingerprint):

    TYPE = "antivirus"

    VERSION = Fingerprint.VERSION_TLS_1_2
    # Kaspersky is the only fp with this EXTENSION + CURVES combo
    EXTENSIONS = [0, 11, 10, 35, 13, 5, 15]
    EC_POINT_FORMATS = [0, 1, 2]
    CURVES = [
        0x000e,
        0x000d,
        0x0019,
        0x000b,
        0x000c,
        0x0018,
        0x0009,
        0x000a,
        0x0016,
        0x0017,
        0x0008,
        0x0006,
        0x0007,
        0x0014,
        0x0015,
        0x0004,
        0x0005,
        0x0012,
        0x0013,
        0x0001,
        0x0002,
        0x0003,
        0x000f,
        0x0010,
        0x0011
    ]
    # vulnerable to CRIME
    MAX_SECURITY = 3
    MAX_MAC_SECURITY = 4

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
        if ua and "Macintosh" in ua:
            return True, self.MAX_MAC_SECURITY

        return True, self.MAX_SECURITY


class Kaspersky20150204(Fingerprint):

    TYPE = "antivirus"
    MAX_SECURITY = 3
    # this looks to just match the ciphers sent by the browser.
    # It does however appear to be the _only_ thing that does
    # compression.
    def match(self, version, ciphers, extensions, headers,
            ec_point_formats, curves, ua, compression):
        if compression != [1,0]:
            return False, None
        if extensions != [0, 11, 10, 35, 13, 5, 15]:
            return False, None
        return True, self.MAX_SECURITY
