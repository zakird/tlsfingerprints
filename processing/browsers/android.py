from browser import *

class AndroidBrowserVersion(BrowserVersion):

    POINT_COMPRESSION_METHODS = None
    COMPRESSION_METHODS2 = [1, 0]

    def invalid_compression_methods(self, compression):
        return compression != self.COMPRESSION_METHODS and compression != self.COMPRESSION_METHODS2


class Android4_0(AndroidBrowserVersion):

    DEFAULT_TLS_VERSION = BrowserVersion.VERSION_TLS_1_0
    CIPHERS = "c014:c00a:0039:0038:c00f:c005:0035:c012:c008:0016:0013:c00d:c003:"
              "000a:c013:c009:0033:0032:c00e:c004:002f:c011:c007:c00c:c002:0005:0004:00ff"
    EXTENSIONS = "0000:000b:000a:0023:3374"
    CURVES = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
              16, 17, 18, 19, 20, 21, 22, 23, 24, 25]


class Android4_1to4_3(AndroidBrowserVersion):
    DEFAULT_TLS_VERSION = BrowserVersion.VERSION_TLS_1_0
    CIPHERS = "c014:c00a:c022:c021:0039:0038:c00f:c005:0035:c012:c008:c01c:c01b"
              ":0016:0013:c00d:c003:000a:c013:c009:c01f:c01e:0033:0032:c00e:c004"
              ":002f:c011:c007:c00c:c002:0005:0004:00ff"
    EXTENSIONS = "0000:000b:000a:0023:3374"
    CURVES = [14, 13, 25, 11, 12, 24, 9, 10, 22, 23, 8, 6, 7, 20, 21, 4, 5, 18, 19, 1, 2, 3, 15, 16, 17]


class Android4_4(AndroidBrowserVersion):

    DEFAULT_TLS_VERSION = BrowserVersion.VERSION_TLS_1_2
    CIPHERS = "c030:c02c:c014:c00a:00a3:009f:006b:006a:0039:0038:009d:003d:0035"
              ":c012:c008:0016:0013:000a:c02f:c02b:c027:c023:c013:c009:00a2:009e:"
              "0067:0040:0033:0032:009c:003c:002f:c011:c007:0005:0004:00ff"
    CIPHERS2 = "c014:c00a:c022:c021:0039:0038:c00f:c005:0035:c012:c008:c01c:c01b:"
               "0016:0013:c00d:c003:000a:c013:c009:c01f:c01e:0033:0032:c00e:c004:"
               "002f:c011:c007:c00c:c002:0005:0004:00ff"
    EXTENSIONS = "0000:000b:000a:0023:000d:3374"
    CURVES = [25, 24, 23]


    def check_valid_ciphers(self, c):
        retv = set(c) - self.ciphers_s
        if retv:
            retv = set(c) - set(self.convert_list(self.CIPHERS2))
        return retv

    def check_valid_cipher_ordering(self, c):
        return True

class Android5_0(AndroidBrowserVersion):

    DEFAULT_TLS_VERSION = BrowserVersion.VERSION_TLS_1_2
    CIPHERS = "cc14:cc13:cc15:c014:c00a:0039:0038:0035:c012:c008:0016:0013:000a:c02f:c02b:c013:c009:00a2:009e:0033:0032:009c:002f:c011:c007:0005:0004:00ff"
    EXTENSIONS = "0000:0023:000d:3374:000b:000a"
    CURVES = [25, 24, 23]


class AndroidBrowser(Browser):

    def __init__(self, *args, **kwargs):
        Browser.__init__(self, *args, **kwargs)
        self.android4_0 = Android4_0()
        self.android4_1to4_3 = Android4_1to4_3()
        self.android4_4 = Android4_4()
        self.android5_0 = Android5_0()

    def get(self, version, os, os_version):
        major_version = version[0]
        if len(version) > 1:
            minor_version = version[1]
        else:
            minor_version = None
        if major_version == 4:
            if minor_version < 1:
                return self.android4_0
            elif minor_version < 4:
                return self.android4_1to4_3
            elif minor_version == 4:
                return self.android4_4
        elif major_version == 5:
            return self.android5_0

    def pretty_version(self, version):
        return version[0]
