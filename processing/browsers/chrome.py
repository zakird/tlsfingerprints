from browser import *

class Chrome(BrowserVersion):

    CURVES = [23, 24, 25]
    POINT_COMPRESSION_METHODS=[0,]
    DEFAULT_VERSION = BrowserVersion.VERSION_TLS_1_2

    def check_valid_cipher_ordering(self, c):
        return True

    def check_valid_ciphers(self, c):
        return set(c) - self.ciphers_s

    def check_valid_extensions(self, c):
        return set(c) - self.extensions_s

    def check_valid_extension_ordering(self, c):
        return True


class Chrome14to23(Chrome):

    CIPHERS = "c00a:c014:0088:0087:0039:0038:c00f:c005:0084:0035:c007:c009:c011"
              ":c013:0045:0044:0066:0033:0032:c00c:c00e:c002:c004:0096:0041:0004"
              ":0005:002f:c008:c012:0016:0013:c00d:c003:feff:000a"
    EXTENSIONS = "0000:ff01:000a:000b:0023:3374:0005"


class Chrome14to23WindowsXP(Chrome14to23):

    CIPHERS = "c014:0088:0087:0039:0038:c00f:0084:0035:c011:c013:0045:0044:"
              "0066:0033:0032:c00c:c00e:0096:0041:0005:0004:002f:c012:0016:0013:c00d:feff:000a"
    CIPHERS2 = []


class Chrome24to28(Chrome):

    CIPHERS = "c00a:c014:0088:0087:0039:0038:c00f:c005:0084:0035:c007:c009:"
              "c011:c013:0045:0044:0066:0033:0032:c00c:c00e:c002:c004:0096:"
              "0041:0005:0004:002f:c008:c012:0016:0013:c00d:c003:feff:000a:"
    EXTENSIONS = "0000:ff01:000a:000b:0023:3374:0005"


class Chrome24to28WindowsXP(Chrome24to28):

    CIPHERS = "c014:0088:0087:0039:0038:c00f:0084:0035:c011:c013:0045:0044:"
              "0066:0033:0032:c00c:c00e:0096:0041:0005:0004:002f:c012:0016:0013:c00d:feff:000a:"
    CIPHERS2 = []


class Chrome29(Chrome):

    CIPHERS = "c00a:c014:0039:006b:0035:003d:c007:c009:c023:c011:c013:c027:0033:0067:0032:0005:0004:002f:003c:000a:"
    EXTENSIONS = "0000:ff01:000a:000b:0023:3374:754f:0005:000d:"


class Chrome29WindowsXP(Chrome29):

    CIPHERS = "c014:0039:006b:0035:003d:c011:c013:c027:0033:0067:0032:0005:0004:002f:003c:000a:"
    CIPHERS2 = []


class Chrome30(Chrome):

    CIPHERS = "c00a:c014:0039:006b:0035:003d:c007:c009:c023:c011:c013:c027:0033:0067:0032:0005:0004:002f:003c:000a:"
    EXTENSIONS = "0000:ff01:000a:000b:0023:3374:0010:754f:0005:000d:"


class Chrome30WindowsXP(Chrome30):

    CIPHERS = "c014:0039:006b:0035:003d:c011:c013:c027:0033:0067:0032:0005:0004:002f:003c:000a"
    CIPHERS2 = []


class Chrome31to32(Chrome):

    CIPHERS = "c02b:c02f:009e:009c:c00a:c014:0039:0035:c007:c009:c011:c013:0033:0032:0005:0004:002f:000a:"
    EXTENSIONS = "0000:ff01:000a:000b:0023:0010:754f:0005:000d:"


class Chrome31to32WindowsXP(Chrome31to32):

    CIPHERS = "c02f:009e:009c:c014:0039:0035:c011:c013:0033:0032:0005:0004:002f:000a"
    CIPHERS2 = []


class Chrome33(Chrome):

    CIPHERS = "c02b:c02f:009e:cc14:cc13:009c:c00a:c014:0039:0035:c007:c009:c011:c013:0033:0032:0005:0004:002f:000a:"
              "cc14:cc13:c02b:c02f:009e:009c:c00a:c014:0039:0035:c007:c009:c011:c013:0033:0032:0005:0004:002f:000a:"
    EXTENSIONS = "0000:ff01:000a:000b:0023:3374:0010:7550:0005:000d:0012:8b47:"
    REQUIRED_EXTENSIONS = '0000:0023:000d:0005:0012:000b:000a:'


class Chrome33WindowsXP(Chrome33):

    CIPHERS = "cc13:c02f:009e:009c:c014:0039:0035:c011:c013:0033:0032:0005:0004:002f:000a"
    CIPHERS2 = []


class Chrome34to35(Chrome):

    CIPHERS = "c02b:c02f:009e:cc14:cc13:c00a:c009:c013:c014:c007:c011:0033:0032:0039:009c:002f:0035:000a:0005:0004:"
              "cc14:cc13:c02b:c02f:009e:c00a:c009:c013:c014:c007:c011:0033:0032:0039:009c:002f:0035:000a:0005:0004:"
    EXTENSIONS = "0000:ff01:000a:000b:0023:3374:0010:7550:0005:000d:0012:8b47"
    REQUIRED_EXTENSIONS = '0000:0023:000d:0005:0012:000b:000a:'


class Chrome34to35WindowsXP(Chrome34to35):

    CIPHERS = "cc13:c02f:009e:c013:c014:c011:0033:0032:0039:009c:002f:0035:000a:0005:0004:"
    CIPHERS2 = []


class Chrome36to38(Chrome):

    CIPHERS = "c02b:c02f:009e:cc14:cc13:c00a:c009:c013:c014:c007:c011:0033:0032:0039:009c:002f:0035:000a:0005:0004:00ff"
              "cc14:cc13:c02b:c02f:009e:c00a:c009:c013:c014:c007:c011:0033:0032:0039:009c:002f:0035:000a:0005:0004:00ff"
    EXTENSIONS = "0000:ff01:000a:000b:0023:3374:0010:7550:0005:0012:000d:0015"
    REQUIRED_EXTENSIONS = '0000:0023:000d:0005:0012:000b:000a:'


class Chromium36to38(Chrome):

    CIPHERS = "c02b:c02f:009e:cc14:cc13:c00a:c009:c013:c014:c007:c011:0033:0032:0039:009c:002f:0035:000a:0005:0004:00ff"
              "cc14:cc13:c02b:c02f:009e:c00a:c009:c013:c014:c007:c011:0033:0032:0039:009c:002f:0035:000a:0005:0004:00ff"
              "cc14:cc13:cc15:c014:c00a:0039:0038:0035:c012:c008:0016:0013:000a:c02f:c02b:c013:c009:00a2:009e:0033:0032:009c:002f:c011:c007:0005:0004:00ff"

    EXTENSIONS = "0000:ff01:000a:000b:0023:0010:7550:0005:0012:000d:0015:000f:"

    def invalid_ec_point_formats(self, methods):
        return False


class Chrome36to38WindowsXP(Chrome36to38):

    CIPHERS = "cc13:c02f:009e:c013:c014:c011:0033:0032:0039:009c:002f:0035:000a:0005:0004:"


class Chrome39(Chrome):
    CIPHERS = "c02f:c02b:009e:cc14:cc13:cc15:c014:c00a:0039:c013:c009:0033:0032:c011:c007:009c:0035:002f:0005:0004:000a:00ff:"
              "cc14:cc13:cc15:c02f:c02b:009e:c014:c00a:0039:c013:c009:0033:0032:c011:c007:009c:0035:002f:0005:0004:000a:00ff:"
    EXTENSIONS = "0000:0023:000d:0005:3374:0012:0010:7550:000b:000a:0015"
                 "0000:ff01:000a:000b:0023:3374:0010:7550:0005:0012:000d:0015"
    REQUIRED_EXTENSIONS = '0000:0023:000d:0005:0012:000b:000a:'


class Chrome39WindowsXP(Chrome39):

    CIPHERS = "cc13:c02f:009e:c013:c014:c011:0033:0032:0039:009c:002f:0035:000a:0005:0004:"


class Chrome40(Chrome):

    EXTENSIONS = "0000:ff01:0017:0023:000d:0005:3374:0012:0010:7550:000b:000a:0015"
                 "0000:ff01:000a:000b:0023:3374:0010:7550:0005:0012:000d:0015"
    CIPHERS = "c02f:c02b:009e:cc14:cc13:cc15:c014:c00a:0039:c013:c009:0033:0032:c011:c007:009c:0035:002f:0005:0004:000a:00ff:"
              "cc14:cc13:cc15:c02f:c02b:009e:c014:c00a:0039:c013:c009:0033:0032:c011:c007:009c:0035:002f:0005:0004:000a:00ff:"
              "c02b:c02f:009e:c00a:c009:c013:c014:c007:c011:0033:0032:0039:009c:002f:0035:000a:0005:0004"
    REQUIRED_EXTENSIONS = '0000:0023:000d:0005:0012:000b:000a:'


class Chrome40WindowsXP(Chrome40):

    CIPHERS = "cc13:c02f:009e:c013:c014:c011:0033:0032:0039:009c:002f:0035:000a:0005:0004"
    CIPHERS2 = []


class Chrome41to42(Chrome):

    EXTENSIONS = "0000:ff01:0017:0023:000d:0005:3374:0012:0010:7550:000b:000a:0015"
    CIPHERS =  "c02b:c02f:009e:cc14:cc13:cc15:c00a:c014:0039:c009:c013:0033:0032:c007:c011:009c:0035:002f:0005:0004:000a:00ff:"
               "cc14:cc13:cc15:c02b:c02f:009e:c00a:c014:0039:c009:c013:0033:0032:c007:c011:009c:0035:002f:0005:0004:000a:00ff:"
               "c02b:c02f:9e:c00a:c009:c013:c014:c007:c011:0033:0032:0039:009c:002f:0035:000a:0005:0004"
    REQUIRED_EXTENSIONS = '0000:0023:000d:0005:0012:000b:000a:'


class Chrome41to42WindowsXP(Chrome41to42):

    CIPHERS = "c02f:009e:cc13:cc15:c014:0039:c013:0033:0032:c011:009c:0035:002f:0005:0004:000a:00ff"
              "cc13:cc15:c02f:009e:c014:0039:c013:0033:0032:c011:009c:0035:002f:0005:0004:000a:00ff"


class Chrome43to45(Chrome):

    EXTENSIONS = "0000:ff01:0017:0023:000d:0005:3374:0012:0010:7550:000b:000a:0015"
                 "0000:ff01:000a:000b:0023:3374:0010:7550:0005:0012:000d:0015"
    CIPHERS =  "c02b:c02f:009e:cc14:cc13:cc15:c00a:c014:0039:c009:c013:0033:0032:009c:0035:002f:000a:00ff:"
               "cc14:cc13:cc15:c02b:c02f:009e:c00a:c014:0039:c009:c013:0033:0032:009c:0035:002f:000a:00ff:"
               "c02b:c02f:009e:c00a:c009:c013:c014:0033:0039:009c:002f:0035:000a"
    REQUIRED_EXTENSIONS = '0000:0023:000d:0005:0012:000b:000a:'


class Chrome43to45WindowsXP(Chrome43to45):

    CIPHERS2 = "c02f:009e:cc13:cc15:c014:0039:c013:0033:009c:0035:002f:000a:00ff"
    CIPHERS  = "cc13:cc15:c02f:009e:c014:0039:c013:0033:009c:0035:002f:000a:00ff"


class Chrome46(Chrome):

    CIPHERS =  "c02b:c02f:009e:cc14:cc13:cc15:c00a:c014:0039:c009:c013:0033:0032:009c:0035:002f:000a"
               "cc14:cc13:cc15:c02b:c02f:009e:c00a:c014:0039:c009:c013:0033:0032:009c:0035:002f:000a"
    EXTENSIONS = "ff01:0000:0017:0023:000d:0005:3374:0012:0010:7550:000b:000a:0015"
    REQUIRED_EXTENSIONS = 'ff01:0000:0023:000d:0005:0012:000b:000a:'


class Chrome46WindowsXP(Chrome46):

    CIPHERS  = "c02f:009e:cc13:cc15:c014:0039:c013:0033:009c:0035:002f:000a:00ff"
               "cc13:cc15:c02f:009e:c014:0039:c013:0033:009c:0035:002f:000a:00ff"


class Chrome47(Chrome):

    CIPHERS  = "c02b:c02f:009e:cc14:cc13:c00a:c014:0039:c009:c013:0033:0032:009c:0035:002f:000a"
    CIPHERS2 = "cc14:cc13:c02b:c02f:009e:c00a:c014:0039:c009:c013:0033:0032:009c:0035:002f:000a"
    EXTENSIONS = "ff01:0000:0017:0023:000d:0005:3374:0012:0010:7550:000b:000a:0015"
    REQUIRED_EXTENSIONS = 'ff01:0000:0023:000d:0005:0012:000b:000a:'


class Chrome47WindowsXP(Chrome47):

    CIPHERS = "c02f:009e:cc13:c014:0039:c013:0033:009c:0035:002f:000a:00ff"
    CIPHERS2 = []


class Chrome48(Chrome):

    CIPHERS = "c02b:c02f:009e:cc14:cc13:c00a:c014:0039:c009:c013:0033:009c:0035:002f:000a"
    EXTENSIONS = "ff01:0000:0017:0023:000d:0005:3374:0012:0010:7550:000b:000a:0015"


class Chrome49to50(Chrome):

    CIPHERS = "c02b:c02f:cca9:cca8:cc14:cc13:c00a:c014:c009:c013:009c:0035:002f:000a"
    EXTENSIONS = "ff01:0000:0017:0023:000d:0005:3374:0012:0010:7550:000b:000a:0015"


class Chrome51(Chrome):

    CIPHERS = "c02b:c02f:c02c:c030:cca9:cca8:cc14:cc13:c009:c013:c00a:c014:009c:009d:002f:0035:000a"
    EXTENSIONS = "ff01:0000:0017:0023:000d:0005:0012:0010:7550:000b:000a:0015"


class Chrome(Browser):

    def __init__(self, *args, **kwargs):
        Browser.__init__(self, *args, **kwargs)
        self.chrome14to23 = Chrome14to23()
        self.chrome24to28 = Chrome24to28()
        self.chrome29 = Chrome29()
        self.chrome30 = Chrome30()
        self.chrome31to32 = Chrome31to32()
        self.chrome33 = Chrome33()
        self.chrome34to35 = Chrome34to35()
        self.chrome36to38 = Chrome36to38()
        self.chromium36to38 = Chromium36to38()
        self.chrome39 = Chrome39()
        self.chrome40 = Chrome40()
        self.chrome41to42 = Chrome41to42()
        self.chrome43to45 = Chrome43to45()
        self.chrome46 = Chrome46()
        self.chrome47 = Chrome47()
        self.chrome48 = Chrome48()
        self.chrome49to50 = Chrome49to50()
        self.chrome51 = Chrome51()

        self.chrome14to23xp = Chrome14to23WindowsXP()
        self.chrome24to28xp = Chrome24to28WindowsXP()
        self.chrome29xp = Chrome29WindowsXP()
        self.chrome30xp = Chrome30WindowsXP()
        self.chrome31to32xp = Chrome31to32WindowsXP()
        self.chrome33xp = Chrome33WindowsXP()
        self.chrome34to35xp = Chrome34to35WindowsXP()
        self.chrome36to38xp = Chrome36to38WindowsXP()
        self.chrome39xp = Chrome39WindowsXP()
        self.chrome40xp = Chrome40WindowsXP()
        self.chrome41to42xp = Chrome41to42WindowsXP()
        self.chrome43to45xp = Chrome43to45WindowsXP()
        self.chrome46xp = Chrome46WindowsXP()
        self.chrome47xp = Chrome47WindowsXP()

    def get_windows_xp(self, version):
        v = version[0]
        if v < 33:
            return None
        if v < 34:
            return self.chrome33xp
        elif v < 36:
            return self.chrome34to35xp
        elif v < 39:
            return self.chrome36to38xp
        elif v < 40:
            return self.chrome39xp
        elif v < 41:
            return self.chrome40xp
        elif v < 43:
            return self.chrome41to42xp
        elif v < 46:
            return self.chrome43to45xp
        elif v < 47:
            return self.chrome46xp
        elif v < 48:
            return self.chrome47xp
        return None


    def get_other(self, version, os):
        v = version[0]
        if (os == "Android" or os == "Linux") and v < 40:
            return None
        if v < 33:
            return None
        if v < 34:
            return self.chrome33
        elif v < 36:
            return self.chrome34to35
        elif v < 39:
            if os == "Ubuntu":
                return self.chromium36to38
            else:
                return self.chrome36to38
        elif v < 40:
            return self.chrome39
        elif v < 41:
            return self.chrome40
        elif v < 43:
            # handle fucked up chromium
            if v == 42 and os == "Ubuntu":
                return None
            return self.chrome41to42
        elif v < 46:
            return self.chrome43to45
        elif v < 47:
            return self.chrome46
        elif v < 48:
            return self.chrome47
        elif v < 49:
            return self.chrome48
        elif v < 51:
            return self.chrome49to50
        elif v < 52:
            return self.chrome51

    def get(self, version, os, os_version):
        if os == "Windows XP":
            return self.get_windows_xp(version)
        else:
            return self.get_other(version, os)

    def pretty_version(self, version):
        return version[0]
