from browser import *

class IEBase(BrowserVersion):

    CURVES = [23,24,25]
    POINT_COMPRESSION_METHODS=[0,]
    CIPHERS2 = []
    EXTENSIONS2 = []

    def __init__(self, *args, **kwargs):
        BrowserVersion.__init__(self, *args, **kwargs)
        self.possible_ciphers = self.POSSIBLE_CIPHERS
        self.possible_ciphers_s = set(self.possible_ciphers)
        self.ciphers_s |= set(self.convert_list(self.CIPHERS2))
        self.possible_ciphers_s |= self.ciphers_s
        self.extensions_s |= set(self.convert_list(self.EXTENSIONS2))
        self.extensions2 = self.convert_list(self.EXTENSIONS2)
        self.curves = set(self.CURVES)

    def check_valid_extension_ordering(self, e):
        return self.is_compatible(self.extensions, e) or \
                self.is_compatible(self.extensions2, e)

    def check_invalid_curves(self, curves):
        return set(curves) - self.curves

    def check_unlikely_ciphers(self, c):
        return set(c) - self.possible_ciphers_s

    def check(self, version, ciphers, extensions, headers,
            ec_point_formats, curves, compression, ua):
        fp = self.fp(version, ciphers, extensions)
        weak_cipher = self.cipher_check.check_any_trivially_broken(ciphers)
        unlikely_cipher = self.check_valid_ciphers(ciphers)
        invalid_cipher = self.check_unlikely_ciphers(ciphers)
        invalid_extensions = self.check_valid_extensions(extensions)
        invalid_extension_ordering = not self.check_valid_extension_ordering(extensions)
        invalid_ec_point_formats = ec_point_formats and self.invalid_ec_point_formats(ec_point_formats)
        invalid_version = self.check_version(version)
        invalid_headers = self.check_invalid_headers(headers)
        missing_extensions = self.check_required_extensions(version, extensions)
        invalid_curves = curves and self.check_invalid_curves(curves)
        invalid_compression = compression != self.COMPRESSION_METHODS

        if invalid_version == self.IMPOSSIBLE:
            valid = self.IMPOSSIBLE
            reason = "invalid_version"
            reason_details = "%s not %s" % (version, self.get_version_name(self.DEFAULT_VERSION))
        elif invalid_extensions:
            valid = self.IMPOSSIBLE
            reason = "invalid_extension"
            reason_details = ",".join(map(lambda x: str(x), invalid_extensions))
        elif invalid_cipher:
            valid = self.IMPOSSIBLE
            reason = "invalid_cipher"
            reason_details = ",".join(map(lambda x: hex(x), invalid_cipher))
        elif invalid_extension_ordering:
            valid = self.IMPOSSIBLE
            reason = "invalid_extension_ordering"
            reason_details = ",".join(map(lambda x: str(x), extensions))
        elif invalid_compression:
            valid = self.IMPOSSIBLE
            reason = "invalid_compression"
            reason_details = ",".join(map(lambda x: str(x), compression))
        elif invalid_curves:
            valid = self.IMPOSSIBLE
            reason = "invalid_curves"
            reason_details = ",".join(map(lambda x: hex(x), curves))
        elif invalid_ec_point_formats:
            valid = self.IMPOSSIBLE
            reason = "invalid_ec_point_formats"
            reason_details = ",".join(map(lambda x: hex(x), ec_point_formats))
        # need to handle this specially because an older TLS version just won't support
        # a bunch of TLS extensions
        elif invalid_version == self.POSSIBLE and missing_extensions:
            valid = self.IMPOSSIBLE
            reason = "missing_extensions"
            reason_details = ",".join(map(lambda x: str(x), missing_extensions))
        elif unlikely_cipher:
            valid = self.UNLIKELY
            reason = "unlikely_cipher"
            reason_details = ",".join(map(lambda x: hex(x), unlikely_cipher))
        elif invalid_version == self.UNLIKELY:
            valid = self.UNLIKELY
            reason = "unlikely_version"
            reason_details = "%s not %s" % (version, self.get_version_name(self.DEFAULT_VERSION))
        elif invalid_headers:
            valid = self.IMPOSSIBLE
            reason = "invalid_headers"
            reason_details = ",".join(invalid_headers)
        else:
            valid = self.POSSIBLE
            reason = reason_details = None
        if valid == self.IMPOSSIBLE or valid == self.UNLIKELY:
            loses_pfs = self.loses_pfs(ciphers)
            old_sec, new_sec = self.change_in_security(version, ciphers)
            mitm, max_sec, mitm_type = self.db.get(self.convert_version(version), ciphers, extensions, headers,
                    ec_point_formats, curves, compression, ua)
            if max_sec and max_sec > new_sec:
                new_sec = max_sec
        else:
            loses_pfs = old_sec = mitm = mitm_type = None
            new_sec = self.security
        zfp = self.zfp(version, ciphers, extensions, curves, valid, mitm)
        bro_fingerprint = self.make_bro_fingerprint(ciphers, curves, extensions,
                ec_point_formats, zfp)

        return {
            "weak_ciphers":weak_cipher,
            "invalid_ciphers":invalid_cipher,
            "bro":bro_fingerprint,
            "invalid_cipher_ordering":None,
            "invalid_extensions":invalid_extensions,
            "invalid_extension_ordering":invalid_extension_ordering,
            "invalid_headers":invalid_headers,
            "missing_extensions":missing_extensions,
            "version":invalid_version,
            "invalid_ec_point_formats":invalid_ec_point_formats,
            "invalid_curves":invalid_curves,
            "unlikely_ciphers":unlikely_cipher,
            "valid":valid,
            "reason":reason,
            "reason_details":reason_details,
            "old_sec":old_sec,
            "new_sec":new_sec,
            "loses_pfs":loses_pfs,
            "mitm":mitm,
            "mitm":mitm_type,
            "fp":fp,
            "zfp":zfp,
            "bro":bro_fingerprint
        }


class WindowsXPAllIE(IEBase):

    # SSL Labs:
    #   Server Name Indication (SNI)    No
    #   Secure Renegotiation    Yes
    #   TLS compression No
    #   Session tickets No
    #   OCSP stapling   No
    #   Signature algorithms    -
    #   Elliptic curves -
    #   Next Protocol Negotiation   No
    #   Application Layer Protocol Negotiation  No
    #   SSL 2 handshake compatibility   Yes

    # Essentially XP supports zero extensions. They did
    # however add support for TLS_EMPTY_RENEGOTIATION_INFO_SCSV


    POSSIBLE_CIPHERS = [
        Ciphers.TLS_RSA_WITH_RC4_128_MD5,
        Ciphers.TLS_RSA_WITH_RC4_128_SHA,
        Ciphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_RSA_WITH_DES_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_DES_CBC_SHA,
        Ciphers.TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,
        Ciphers.TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,
        Ciphers.TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA,
        Ciphers.TLS_RSA_EXPORT_WITH_RC4_40_MD5,
        Ciphers.TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
        Ciphers.TLS_RSA_WITH_NULL_MD5,
        Ciphers.TLS_RSA_WITH_NULL_SHA,
        Ciphers.TLS_RENEGO_PROTECTION_REQUEST
    ]
    CIPHERS = "0004:0005:000a:0009:0064:0062:0003:0006:0013:0012:0063:00ff"
    EXTENSIONS = []
    CURVES = []
    MAX_VERSION = BrowserVersion.VERSION_TLS_1_0
    DEFAULT_VERSION = BrowserVersion.VERSION_TLS_1_0



class RecentWindows(IEBase):

    POSSIBLE_CIPHERS = [
        Ciphers.TLS_RSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_RSA_WITH_AES_256_CBC_SHA256,
        Ciphers.TLS_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_RSA_WITH_RC4_128_SHA,
        Ciphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        Ciphers.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
        Ciphers.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
        Ciphers.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_RSA_WITH_RC4_128_MD5,
        Ciphers.SSL_CK_RC4_128_WITH_MD5,
        Ciphers.SSL_CK_DES_192_EDE3_CBC_WITH_MD5,
        Ciphers.TLS_RSA_WITH_NULL_SHA256,
        Ciphers.TLS_RSA_WITH_NULL_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        Ciphers.TLS_RSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_RSA_WITH_AES_256_GCM_SHA384,
        Ciphers.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        Ciphers.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
    ]

class Windows7IE8to9(RecentWindows):

    # SSL Labs:
    #   0x0000  Server Name Indication (SNI)    Yes
    #   0xff01  Secure Renegotiation    Yes
    #   0x0023  Session tickets No
    #   0x0005  OCSP stapling   Yes
    #   0x000d  Signature algorithms    No
    #   0x000a  Elliptic curves
    #               secp256r1,  secp384r1,  secp521r1
    #   0x3374  Next Protocol Negotiation   No
    #   0x0010  Application Layer Protocol Negotiation  No
    #   0x000b  EC Point Formats

    CIPHERS = "002f:0035:0005:000a:c009:c00a:c013:c014:0032:0038:0013:0004"
    CIPHERS2 = "c030:c02f:c028:c027:c014:c013:009f:009e:009d:009c:003d:003c:"\
               "0035:002f:c02c:c02b:c024:c023:c00a:c009:006a:0040:0038:0032:000a:0013"
    EXTENSIONS = "ff01:0000:0005:000a:000b:ff01"
    EXTENSIONS2 = [65281, 0, 5, 10, 11, 13, 23, 65281]
    # This is what
    # while we're not sure if IE originally support TLS master secret, it
    # appears that later patches added support for it:
    # https://technet.microsoft.com/en-us/library/security/ms15-121.aspx
    #EXTENSIONS2 = [0, 5, 10, 11, 23, 65281]
    MAX_VERSION = BrowserVersion.VERSION_TLS_1_2
    DEFAULT_VERSION = BrowserVersion.VERSION_TLS_1_0
    REQUIRED_EXTENSIONS = '0000:000a:000b:ff01'


class Windows8(RecentWindows):

    CIPHERS = "003c:002f:003d:0035:0005:000a:c027:c013:c014:c02b:c023:c02c:c024"\
              ":c009:c00a:0040:0032:006a:0038:0013:0004"

    # https://www.ssllabs.com/ssltest/viewClient.html?name=IE&version=11&platform=Win%208.1&key=104
    CIPHERS2 = "c028:c027:c014:c013:009f:009e:009d:009c:003d:003c:0035"\
               ":002f:c02c:c02b:c024:c023:c00a:c009:006a:0040:0038:0032:000a:0013"
    EXTENSIONS = "ff01:0000:0005:000a:000b:000d:0023"
    EXTENSIONS2 = [65281, 0, 5, 10, 11, 13, 35, 16, 23, 13172, 65281]
    MAX_VERSION = BrowserVersion.VERSION_TLS_1_2
    DEFAULT_VERSION = BrowserVersion.VERSION_TLS_1_2
    REQUIRED_EXTENSIONS = 'ff01:0000:000a:000b:000d'


class Windows10IE11(RecentWindows):

    CIPHERS = "c030:c02f:c028:c027:c014:c013:009f:009e:009d:009c:003d:003c:"\
              "0035:002f:c02c:c02b:c024:c023:c00a:c009:006a:0040:0038:0032:000a:0013"
    EXTENSIONS = "0000:0005:000a:000b:000d:0023:0010:0017:5500:ff01"
    MAX_VERSION = BrowserVersion.VERSION_TLS_1_2
    DEFAULT_VERSION = BrowserVersion.VERSION_TLS_1_2
    REQUIRED_EXTENSIONS = 'ff01:0000:000a:000b:000d'


class Windows10IE12(RecentWindows):

    CIPHERS = "c030:c02f:c028:c027:c014:c013:009f:009e:009d:009c:003d:003c:"\
              "0035:002f:c02c:c02b:c024:c023:c00a:c009:006a:0040:0038:0032:000a:0013"
    EXTENSIONS = "0000:0005:000a:000b:000d:0023:0010:0017:5500:ff01"
    MAX_VERSION = BrowserVersion.VERSION_TLS_1_2
    DEFAULT_VERSION = BrowserVersion.VERSION_TLS_1_2
    REQUIRED_EXTENSIONS = 'ff01:0000:000a:000b:000d'


class Windows81IE11(RecentWindows):

    CIPHERS = "003c:002f:003d:0035:000a:c027:c013:c014:c02b:c023:c02c:c024:"\
              "c009:c00a:0040:0032:006a:0038:0013"


class WindowsVista(IEBase):

    POSSIBLE_CIPHERS = [
        Ciphers.TLS_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_RSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_RSA_WITH_RC4_128_SHA,
        Ciphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
        Ciphers.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
        Ciphers.TLS_RSA_WITH_RC4_128_MD5,
        Ciphers.SSL_CK_RC4_128_WITH_MD5,
        Ciphers.SSL_CK_DES_192_EDE3_CBC_WITH_MD5,
        Ciphers.TLS_RSA_WITH_NULL_MD5,
        Ciphers.TLS_RSA_WITH_NULL_SHA,
    ]

    CIPHERS = "002f:0035:0005:000a:c009:c00a:c013:c014:0032:0038:0013:0004"
    CIPHERS2 = "c030:c02f:c028:c027:c014:c013:009f:009e:009d:009c:003d:003c:"\
               "0035:002f:c02c:c02b:c024:c023:c00a:c009:006a:0040:0038:0032:000a:0013"
    EXTENSIONS = "ff01:0000:0005:000a:000b:ff01"
    EXTENSIONS2 = [65281, 0, 5, 10, 11, 13, 23, 65281]


class InternetExplorer(Browser):

    def __init__(self, *args, **kwargs):
        Browser.__init__(self, *args, **kwargs)
        self.windowsXP = WindowsXPAllIE()
        self.windows7ie8to9 = Windows7IE8to9()
        self.windows8 = Windows8()
        self.windows10ie11 = Windows10IE11()
        self.windows10ie12 = Windows10IE12()
        self.windowsVista = WindowsVista()

    def get(self, version, os, os_version):
        v = version[0]
        if os == "Windows XP":
            return self.windowsXP
        elif os == "Windows Vista":
            return self.windowsVista
        if os == "Windows 7":
            if v in (7, 8, 9, 10):
                return self.windows7ie8to9
            elif v in (11,):
                return self.windows8
        elif os in ("Windows 8", "Windows 8.1"):
            return self.windows8
        elif os == "Windows 10":
            if v >= 12:
                return self.windows10ie12
            elif v > 9:
                return self.windows10ie11


    def pretty_version(self, version):
        return version[0]

