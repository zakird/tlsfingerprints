from browser import *

class Firefox3to12(BrowserVersion):

    CIPHERS = "00ff:c00a:c014:0088:0087:0039:0038:c00f:c005:0084:0035:c007:c009"\
        ":c011:c013:0045:0044:0033:0032:c00c:c00e:c002:c004:0096:0041:0004:0005:"\
        "002f:c008:c012:0016:0013:c00d:c003:feff:000a"
    EXTENSIONS = "0000:000a:000b:0023"
    DEFAULT_VERSION = BrowserVersion.VERSION_TLS_1_0
    REQUIRED_EXTENSIONS = "0000:000a:000b:0023"
    POINT_COMPRESSION_METHODS=[0,]
    CURVES = [23,24,25]


class Firefox13to24(BrowserVersion):

    CIPHERS = "00ff:c00a:c014:0088:0087:0039:0038:c00f:c005:0084:0035:c007:"\
            "c009:c011:c013:0045:0044:0033:0032:c00c:c00e:c002:c004:0096:0041"\
            ":0005:0004:002f:c008:c012:0016:0013:c00d:c003:feff:000a"
    EXTENSIONS = "0000:000a:000b:0023:3374"
    DEFAULT_VERSION = BrowserVersion.VERSION_TLS_1_0
    REQUIRED_EXTENSIONS = "0000:000a:000b:0023:3374"
    POINT_COMPRESSION_METHODS=[0,]
    CURVES = [23,24,25]


class Firefox25(BrowserVersion):

    CIPHERS = "00ff:c00a:c014:0088:0087:0039:0038:c00f:c005:0084:0035:c009:c007"\
              ":c013:c011:0045:0044:0033:0032:c00e:c00c:c004:c002:0096:0041:002f"\
              ":0005:0004:c008:c012:0016:0013:c00d:c003:feff:000a"
    EXTENSIONS = "0000:000a:000b:0023:3374"
    DEFAULT_VERSION = BrowserVersion.VERSION_TLS_1_0
    REQUIRED_EXTENSIONS = "0000:000a:000b:0023:3374"
    POINT_COMPRESSION_METHODS=[0,]
    CURVES = [23,24,25]


class Firefox26(BrowserVersion):

    CIPHERS = "00ff:c00a:c014:0088:0087:0039:0038:c00f:c005:0084:0035:c009:c007"\
        ":c013:c011:0045:0044:0033:0032:c00e:c00c:c004:c002:0096:0041:002f:0005"\
        ":0004:c008:c012:0016:0013:c00d:c003:feff:000a"
    EXTENSIONS = "0000:000a:000b:0023:3374:0005:0015"
    DEFAULT_VERSION = BrowserVersion.VERSION_TLS_1_0
    REQUIRED_EXTENSIONS = "0000:000a:000b:0023:3374"
    POINT_COMPRESSION_METHODS=[0,]
    CURVES = [23,24,25]


class Firefox27to32(BrowserVersion):

    CIPHERS = "c02b:c02f:c00a:c009:c013:c014:c012:c007:c011:0033:0032:0045:"\
            "0039:0038:0088:0016:002f:0041:0035:0084:000a:0005:0004:00ff"
    EXTENSIONS = "0000:ff01:000a:000b:0023:3374:0005:000d:8b47:0015"
    DEFAULT_VERSION = BrowserVersion.VERSION_TLS_1_2
    REQUIRED_EXTENSIONS = "0000:ff01:000a:000b:0023:3374:000d"
    POINT_COMPRESSION_METHODS=[0,]
    CURVES = [23,24,25]


class Firefox33(BrowserVersion):

    CIPHERS = "c02b:c02f:c00a:c009:c013:c014:c007:c011:0033:0032:0039:002f:0035:000a:0005:0004:00ff"
    EXTENSIONS = "0000:ff01:000a:000b:0023:3374:0005:000d:0015"
    DEFAULT_VERSION = BrowserVersion.VERSION_TLS_1_2
    REQUIRED_EXTENSIONS = "0000:ff01:000a:000b:0023:3374:000d"
    POINT_COMPRESSION_METHODS=[0,]
    CURVES = [23,24,25]


class Firefox34to35(BrowserVersion):

    CIPHERS = "c02b:c02f:c00a:c009:c013:c014:c007:c011:0033:0032:0039:002f:0035:000a:0005:0004:00ff"
    EXTENSIONS = "0000:ff01:000a:000b:0023:3374:0010:0005:000d:0015"
    DEFAULT_VERSION = BrowserVersion.VERSION_TLS_1_2
    REQUIRED_EXTENSIONS = "0000:ff01:000a:000b:0023:3374:0010:000d"
    POINT_COMPRESSION_METHODS=[0,]
    CURVES = [23,24,25]


class Firefox36(BrowserVersion):

    CIPHERS = "c02b:c02f:c00a:c009:c013:c014:0033:0032:0039:002f:0035:000a:00ff"
    EXTENSIONS = "0000:ff01:000a:000b:0023:3374:0010:0005:000d:0015"
    DEFAULT_VERSION = BrowserVersion.VERSION_TLS_1_2
    REQUIRED_EXTENSIONS = "0000:ff01:000a:000b:0023:3374:0010:000d"
    POINT_COMPRESSION_METHODS=[0,]
    CURVES = [23,24,25]


class Firefox37to43(BrowserVersion):

    CIPHERS = "c02b:c02f:c00a:c009:c013:c014:0033:0039:002f:0035:000a"
    EXTENSIONS = "0000:ff01:000a:000b:0023:3374:0010:0005:000d:0015"
    DEFAULT_VERSION = BrowserVersion.VERSION_TLS_1_2
    REQUIRED_EXTENSIONS = "0000:ff01:000a:000b:0023:3374:0010:000d"
    POINT_COMPRESSION_METHODS=[0,]
    CURVES = [23,24,25]


class Firefox44to45(BrowserVersion):

    CIPHERS = "c02b:c02f:c00a:c009:c013:c014:0033:0039:002f:0035:000a"
    EXTENSIONS = "0000:ff01:000a:000b:0023:3374:0010:0005:000d:0017:0015"
    DEFAULT_VERSION = BrowserVersion.VERSION_TLS_1_2
    REQUIRED_EXTENSIONS = "0000:ff01:000a:000b:0023:3374:0010:000d"
    POINT_COMPRESSION_METHODS=[0,]
    CURVES = [23,24,25]


class Firefox46(BrowserVersion):

    CIPHERS = "c02b:c02f:c00a:c009:c013:c014:0033:0039:002f:0035:000a"
    EXTENSIONS = "0000:0017:ff01:000a:000b:0023:3374:0010:0005:000d:0015"
    DEFAULT_VERSION = BrowserVersion.VERSION_TLS_1_2
    REQUIRED_EXTENSIONS = "0000:ff01:000a:000b:0023:3374:0010:000d"
    POINT_COMPRESSION_METHODS=[0,]
    CURVES = [23,24,25]

class Firefox47(BrowserVersion):

    CIPHERS = "c02b:c02f:cca9:cca8:c00a:c009:c013:c014:0033:0039:002f:0035:000a"
    EXTENSIONS = "0000:0017:ff01:000a:000b:0023:3374:0010:0005:000d:0015"
    DEFAULT_VERSION = BrowserVersion.VERSION_TLS_1_2
    REQUIRED_EXTENSIONS = "0000:ff01:000a:000b:0023:3374:0010:000d"
    POINT_COMPRESSION_METHODS=[0,]
    CURVES = [23,24,25]


class Firefox(Browser):

    def __init__(self, *args, **kwargs):
        Browser.__init__(self, *args, **kwargs)
        self.firefox3to12 = Firefox3to12()
        self.firefox13to24 = Firefox13to24()
        self.firefox25 = Firefox25()
        self.firefox26 = Firefox26()
        self.firefox27to32 = Firefox27to32()
        self.firefox33 = Firefox33()
        self.firefox34to35 = Firefox34to35()
        self.firefox36 = Firefox36()
        self.firefox37to43 = Firefox37to43()
        self.firefox44to45 = Firefox44to45()
        self.firefox46 = Firefox46()
        self.firefox47 = Firefox47()

    def pretty_version(self, version):
        return version[0]

    def get(self, version, os, os_version):
        v = version[0]
        if v < 3:
            return None
        if v < 13:
            return self.firefox3to12
        elif v < 25:
            return self.firefox13to24
        elif v == 25:
            return self.firefox25
        elif v == 26:
            return self.firefox26
        elif v < 33:
            return self.firefox27to32
        elif v == 33:
            return self.firefox33
        elif v < 36:
            return self.firefox34to35
        elif v == 36:
            return self.firefox36
        elif v < 44:
            return self.firefox37to43
        elif v < 46:
            return self.firefox44to45
        elif v < 47:
            return self.firefox46
        elif v < 48:
            return self.firefox47
        else:
            return None
