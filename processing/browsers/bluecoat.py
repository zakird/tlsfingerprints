from browser import *

class Bluecoat(BrowserVersion):

    CIPHERS = [52244, 52243, 52245, 49199, 49195, 158, 49172, 49162, 57, 49171,
            49161, 51, 49169, 49159, 156, 53, 47, 5, 4, 10, 255]

    CIPHERS2 =[49172,49162,57,56,53,49170,49160,22,19,10,49199,49195,49171,
            49161,162,158,51,50,156,47,49169,49159,5,4,255]


    EXTENSIONS = [0x0, 0x23, 0xd, 0x5, 0x3374, 0x12, 0x7550, 0xb, 0xa, 0x15]
    DEFAULT_VERSION = BrowserVersion.VERSION_TLS_1_2
    POINT_COMPRESSION_METHODS=[0,]
    CURVES = [23,24,25]



class Silk(Browser):

    def __init__(self, *args, **kwargs):
        Browser.__init__(self, *args, **kwargs)
        self.silk3 = Silk3()

    def pretty_version(self, version):
        return version[0]

    def get(self, version, os, os_version):
        v = version[0]
        if v == 3:
            return self.silk3

