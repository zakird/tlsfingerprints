from browser import *


class SafariVersion(BrowserVersion):

    POINT_COMPRESSION_METHODS=[0,]
    CURVES = [23, 24, 25]
    CIPHERS2 = []
    CIPHERS3 = []

    def __init__(self, *args, **kwargs):
        BrowserVersion.__init__(self, *args, **kwargs)
        self.ciphers2 = self.convert_list(self.CIPHERS2)
        self.ciphers2_s = set(self.ciphers2)
        self.ciphers3 = self.convert_list(self.CIPHERS3)
        self.ciphers3_s = set(self.ciphers3)

    def check_valid_ciphers(self, c):
        retv = set(c) - self.ciphers_s
        if retv:
            retv = set(c) - self.ciphers2_s
        if retv:
            retv = set(c) - self.ciphers3_s
        return retv

    def check_valid_cipher_ordering(self, c):
        return self.is_compatible(self.ciphers, c) or \
                self.is_compatible(self.ciphers2, c) or \
                self.is_compatible(self.ciphers3, c)


class Safari9(SafariVersion):

    # SSL Labs:
    #   0x0000  Server Name Indication (SNI)    Yes
    #   0xff01  Secure Renegotiation    Yes
    #   0x0023  Session tickets No
    #   0x0005  OCSP stapling   Yes
    #   0x000d  Signature algorithms    SHA384/RSA, SHA256/RSA, SHA1/RSA,   SHA384/ECDSA,
    #                                   SHA256/ECDSA, SHA1/ECDSA
    #   0x000a  Elliptic curves
    #               secp256r1,  secp384r1,  secp521r1
    #   0x3374  Next Protocol Negotiation   Yes
    #   0x0010  Application Layer Protocol Negotiation  Yes   spdy/3 h2-15 http/1.1 h2-14
    #                                           spdy/3.1 h2-16 h2
    #   0x000b  EC Point Formats

    DEFAULT_TLS_VERSION = BrowserVersion.VERSION_TLS_1_2
    CIPHERS = '00ff:c02c:c02b:c024:c023:c00a:c009:c008:c030:c02f:c028:c027:'\
              'c014:c013:c012:009d:009c:003d:003c:0035:002f:000a:c007:c011:0005:0004:'
    CIPHERS2 = [0xff, 0xc024, 0xc023, 0xc00a, 0xc009, 0xc008, 0xc028, 0xc027,
            0xc014, 0xc013, 0xc012, 0xc026, 0xc025, 0xc005, 0xc004, 0xc003,
            0xc02a, 0xc029, 0xc00f, 0xc00e, 0xc00d, 0x6b, 0x67, 0x39, 0x33,
            0x16, 0x3d, 0x3c, 0x35, 0x2f, 0xa, 0xc007, 0xc011, 0xc002, 0xc00c,
            0x5, 0x4]
    CIPHERS3 = '00ff:c024:c023:c00a:c009:c007:c008:c028:c027:c014:c013:c011:'\
            'c012:c026:c025:c02a:c029:c005:c004:c002:c003:c00f:c00e:c00c:c00d:'\
            '003d:003c:002f:0005:0004:0035:000a:0067:006b:0033:0039:0016'
    # These extensions confirmed in examined client hello
    EXTENSIONS = '0000:000a:000b:000d:3374:0010:0005:0012:0015'
    REQUIRED_EXTENSIONS = [0, 10, 11, 13]


class Safari8(SafariVersion):

    # SSL Labs:
    #   0x0000  Server Name Indication (SNI)    Yes
    #   0xff01  Secure Renegotiation    Yes
    #   0x0023  Session tickets No
    #   0x0005  OCSP stapling   No
    #   0x000d  Signature algorithms    SHA384/RSA, SHA256/RSA, SHA1/RSA, SHA256/ECDSA, SHA1/ECDSA
    #   0x000a  Elliptic curves
    #               secp256r1,  secp384r1,  secp521r1
    #   0x3374  Next Protocol Negotiation   Yes
    #   0x0010  Application Layer Protocol Negotiation  No
    #   0x000b  EC Point Formats

    DEFAULT_TLS_VERSION = BrowserVersion.VERSION_TLS_1_2
    CIPHERS = '00ff:c024:c023:c00a:c009:c008:c028:c027:c014:c013:c012:c026:'\
              'c025:c005:c004:c003:c02a:c029:c00f:c00e:c00d:006b:0067:0039:'\
              '0033:0016:003d:003c:0035:002f:000a:c007:c011:c002:c00c:0005:0004:'
    EXTENSIONS = '0000:000a:000b:000d:3374:'
    REQUIRED_EXTENSIONS = [0, 10, 11, 13]


class Safari7(SafariVersion):

    # SSL Labs:
    #   Session Tickets: no
    #   OCSP stapling: no
    #   NPN: no
    #   ALPN: no
    #   Signature Algorithms: SHA384/RSA,   SHA256/RSA, SHA1/RSA,
    #   SHA256/ECDSA,   SHA1/ECDSA
    #   Curves: secp256r1,  secp384r1,  secp521r1

    DEFAULT_TLS_VERSION = BrowserVersion.VERSION_TLS_1_2

    CIPHERS = '00ff:c024:c023:c00a:c009:c007:c008:c028:c027:c014:c013:c011:'\
              'c012:c026:c025:c02a:c029:c005:c004:c002:c003:c00f:c00e:c00c:'\
              'c00d:003d:003c:002f:0005:0004:0035:000a:0067:006b:0033:0039:0016'
    EXTENSIONS = '0000:000a:000b:000d'
    REQUIRED_EXTENSIONS = [0, 10, 11, 13]


class Safari6(SafariVersion):

    # SSL Labs:
    #   Session Tickets: no
    #   OCSP stapling: no
    #   NPN: no
    #   ALPN: no
    #   Signature Algorithms: none

    CIPHERS = "c00a:c009:c007:c008:c013:c014:c011:c012:c004:c005:c002:c003:"\
              "c00e:c00f:c00c:c00d:002f:0005:0004:0035:000a:0032:0033:0038:"\
              "0039:0016:0013"
    CIPHERS2 = "00ff:c00a:c009:c007:c008:c014:c013:c011:c012:c004:c005:c002:"\
               "c003:c00e:c00f:c00c:c00d:002f:0005:0004:0035:000a:0033:0039:0016"
    EXTENSIONS = "0000:000a:000b"
    REQUIRED_EXTENSIONS = [0, 10, 11]


class Safari5(SafariVersion):

    CIPHERS = 'c00a:c009:c007:c008:c013:c014:c011:c012:c004:c005:c002:c003:'\
              'c00e:c00f:c00c:c00d:002f:0005:0004:0035:000a:0009:0003:0008:'\
              '0006:0032:0033:0038:0039:0016:0015:0014:0013:0012:0011:'
    EXTENSIONS = '0000:000a:000b'
    REQUIRED_EXTENSIONS = [0, 10, 11]


class MobileSafari9(SafariVersion):

    # SSL Labs:
    #   0x0000  Server Name Indication (SNI)    Yes
    #   0xff01  Secure Renegotiation    Yes
    #   0x0023  Session tickets No
    #   0x0005  OCSP stapling   Yes
    #   0x000d  Signature algorithms    SHA384/RSA, SHA256/RSA, SHA1/RSA,   SHA384/ECDSA,
    #                                   SHA256/ECDSA, SHA1/ECDSA
    #   0x000a  Elliptic curves
    #               secp256r1,  secp384r1,  secp521r1
    #   0x3374  Next Protocol Negotiation   Yes
    #   0x0010  Application Layer Protocol Negotiation  Yes   spdy/3 h2-15 http/1.1 h2-14
    #                                           spdy/3.1 h2-16 h2
    #   0x000b  EC Point Formats

    CIPHERS =  "00ff:c02c:c02b:c024:c023:c00a:c009:c008:c030:c02f:c028:c027:c014"\
               ":c013:c012:009d:009c:003d:003c:0035:002f:000a:c007:c011:0005:0004:"
    EXTENSIONS = '0000:000a:000b:000d:3374:0010:0005:0012:0015'
    REQUIRED_EXTENSIONS = [0, 10, 11, 13]


class MobileSafari8(SafariVersion):

    # SSL Labs
    #   Server Name Indication (SNI)    Yes
    #   Secure Renegotiation    Yes
    #   TLS compression No
    #   Session tickets No
    #   OCSP stapling   No
    #   Signature algorithms    SHA384/RSA, SHA256/RSA, SHA1/RSA,   SHA256/ECDSA,
    #   SHA1/ECDSA
    #   Elliptic curves secp256r1,  secp384r1,  secp521r1
    #   Next Protocol Negotiation   Yes
    #   Application Layer Protocol Negotiation  No

    # Note: we noticed a large number of clients that have the extensions:
    # 65281,35,5,16,18,21. We neither see  support for OCSP nor session
    # tickets in our handshakes. It looks like Ivan's analysis is the same
    # as ours.

    CIPHERS = '00ff:c024:c023:c00a:c009:c008:c028:c027:c014:c013:c012:c026:'\
              'c025:c005:c004:c003:c02a:c029:c00f:c00e:c00d:006b:0067:0039:0033'\
              ':0016:003d:003c:0035:002f:000a:c007:c011:c002:c00c:0005:0004:'
    CIPHERS2 = [0xc013,0xc009,0xc00a,0xc02b,0x9e,0xc02f,0x33,0xcc13,
                 0x35,0x39,0xcc14,0x2f,0x9c,0xa,0xc014]
    EXTENSIONS = '0000:000a:000b:000d:00ff:3374'
    REQUIRED_EXTENSIONS = [0, 10, 11, 13]


class MobileSafari7(SafariVersion):

    CIPHERS = "00ff:c024:c023:c00a:c009:c007:c008:c028:c027:c014:c013:c011:c012"
              ":c026:c025:c02a:c029:c005:c004:c002:c003:c00f:c00e:c00c:c00d:003d"
              ":003c:002f:0005:0004:0035:000a:0067:006b:0033:0039:0016"
    EXTENSIONS = '0000:000a:000b:000d:3374'
    REQUIRED_EXTENSIONS = [0, 10, 11, 13]


class MobileSafari6(SafariVersion):

    CIPHERS = '00ff:c024:c023:c00a:c009:c007:c008:c028:c027:c014:c013:c011:'
              'c012:c026:c025:c02a:c029:c004:c005:c002:c003:c00e:c00f:c00c:'
              'c00d:003d:003c:002f:0005:0004:0035:000a:0067:006b:0033:0039:'
              '0016:c006:c010:c001:c00b:003b:0002:0001'
    EXTENSIONS = '0000:000a:000b:000d:3374'
    REQUIRED_EXTENSIONS = [0, 10, 11, 13]


class MobileSafari5(SafariVersion):

    CIPHERS = "00ff:c024:c023:c00a:c009:c007:c008:c028:c027:c014:c013:c011"
              ":c012:c026:c025:c02a:c029:c004:c005:c002:c003:c00e:c00f:c00c"
              ":c00d:003d:003c:002f:0005:0004:0035:000a:0067:006b:0033:0039:0016"
    EXTENSIONS = '0000:000a:000b:000d:3374'
    REQUIRED_EXTENSIONS = [0, 10, 11, 13]


class Safari(Browser):

    def __init__(self, *args, **kwargs):
        Browser.__init__(self, *args, **kwargs)
        self.safari5 = Safari5()
        self.safari6 = Safari6()
        self.safari7 = Safari7()
        self.safari8 = Safari8()
        self.safari9 = Safari9()

    def get(self, version, os, os_version):
        if not os.startswith("Mac OS"):
            return None
        if version:
            v = version[0]
        else:
            return None
        if v < 5:
            return None
        if v == 5:
            return self.safari5
        elif v == 6:
            return self.safari6
        elif v == 7:
            return self.safari7
        elif v == 8:
            return self.safari8
        elif v == 9:
            return self.safari9

    def pretty_version(self, v):
        return v[0]


class MobileSafari(Browser):

    def __init__(self, *args, **kwargs):
        Browser.__init__(self, *args, **kwargs)
        self.safari5 = MobileSafari5()
        self.safari6 = MobileSafari6()
        self.safari7 = MobileSafari7()
        self.safari8 = MobileSafari8()
        self.safari9 = MobileSafari9()

    def get(self, version, os, os_version):
        if not version:
            return None
        v = version[0]
        if v < 5:
            return None
        if v == 5:
            return self.safari5
        elif v == 6:
            return self.safari6
        elif v == 7:
            return self.safari7
        elif v == 8:
            return self.safari8
        elif v == 9:
            return self.safari9

    def pretty_version(self, v):
        return v[0]

