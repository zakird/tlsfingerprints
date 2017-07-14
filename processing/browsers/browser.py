import hashlib
import copy

from mitmengine.fingerprints import *
from mitmengine.ciphers import *
from mitmengine.fpdb import *


class Browser(object):
    pass


class BrowserVersion(object):

    IMPOSSIBLE = "IMPOSSIBLE"
    UNLIKELY = "UNLIKELY"
    POSSIBLE = "POSSIBLE"

    VERSION_SSL_2 = 1
    VERSION_SSL_3 = 2
    VERSION_TLS_1_0 = 3
    VERSION_TLS_1_1 = 4
    VERSION_TLS_1_2 = 5
    VERSION_TLS_1_3 = 6

    DEFAULT_VERSION = None
    MIN_VERSION = 2  # nobody offers SSLv2 handshakes.
    MAX_VERSION = None

    REQUIRED_EXTENSIONS = []
    CURVES = []
    POINT_COMPRESSION_METHODS = [0, ]
    COMPRESSION_METHODS = [0, ]

    @classmethod
    def get_version_name(cls, n):
        if n == cls.VERSION_SSL_2:
            return "2"
        elif n == cls.VERSION_SSL_3:
            return "3"
        elif n == cls.VERSION_TLS_1_0:
            return "3.1"
        elif n == cls.VERSION_TLS_1_1:
            return "3.2"
        elif n == cls.VERSION_TLS_1_2:
            return "3.3"
        elif n == cls.VERSION_TLS_1_3:
            return "3.4"

    def __init__(self):
        self.ciphers = self.convert_list(self.CIPHERS)
        self.ciphers_s = set(self.ciphers)
        self.extensions = self.convert_list(self.EXTENSIONS)
        self.extensions_s = set(self.extensions)
        self.required_extensions = set(
            self.convert_list(self.REQUIRED_EXTENSIONS))
        self.cipher_check = CipherCheck()
        self.db = FingerprintDatabase()
        self.ciphercheck = CipherCheck()
        self.pfs = self.ciphercheck.is_first_pfs(self.ciphers)
        self.security = self.ciphercheck.get_security(self.ciphers)

    def convert_list(self, l):
        if type(l) == list:
            return l
        else:
            return map(lambda x: int(x, 16), l.rstrip(":").split(":"))

    def is_compatible(self, truth, test):
        def iter_truth(l, to_find):
            while l:
                if l.pop(0) == to_find:
                    return True, l
            return False, []
        t = copy.copy(truth)
        for element in test:
            found, t = iter_truth(t, element)
            if not found:
                return False
        return True

    def check_valid_ext_ordering(self, e):
        return self.is_compatible(self.extensions, e)

    def check_valid_cipher_ordering(self, c):
        return self.is_compatible(self.ciphers, c)

    def check_valid_ciphers(self, c):
        return set(c) - self.ciphers_s

    def check_valid_extensions(self, exts):
        return set(exts) - self.extensions_s

    def check_valid_extension_ordering(self, exts):
        return self.is_compatible(self.extensions, exts)

    def check_required_extensions(self, version, exts):
        return self.required_extensions - set(exts)

    def convert_version(self, version):
        if not version:
            return None
        elif str(version) == "2":
            return self.VERSION_SSL_2
        if str(version) == "3.0" or version == 768:
            return self.VERSION_SSL_3
        elif str(version) == "3.1" or version == 769:
            return self.VERSION_TLS_1_0
        elif str(version) == "3.2" or version == 770:
            return self.VERSION_TLS_1_1
        elif str(version) == "3.3" or version == 771:
            return self.VERSION_TLS_1_2
        elif str(version) == "3.4":
            return self.VERSION_TLS_1_3
        else:
            raise Exception("Unknown version: %s" % version)

    def check_version(self, version):
        if type(version) in (str, unicode, int):
            version = self.convert_version(version)
        if not version:
            return self.POSSIBLE
        if self.MIN_VERSION and version < self.MIN_VERSION:
            return self.IMPOSSIBLE
        if self.MAX_VERSION and version > self.MAX_VERSION:
            return self.IMPOSSIBLE
        if float(version) < self.DEFAULT_VERSION:
            return self.UNLIKELY
        return self.POSSIBLE

    BAD_HEADERS = set([
        "X-BlueCoat-Via",
        "X-MDS-TDestination-IP",
        "X-IWSaaS-Via",
        "True-client-IP",
        "x-forwarded-Proto",
        "x-wap-proxy-cookie",
        "Via",
        "X-MWG-Via",
        "Proxy-Connection",
        "X-forwarded-for",
        "x-forwardded-for",
        "x-forward",
        "Z-Forwarded-For",
        "X-Real-Ip",
        "X-Originating-IP",
        "X-Forwardded-For",
        "x-forward-for",
        "True-Client-IP",
        "x-forwared-for",
        "x-Forward-For",
        "X-Forwarded-Proto",
        "EdgeWave-Proxy",
        "X-Fordwarded-For",
        "X-Forwarded-for",
        "X-Forwarded-For",
        "S-Forwarded-For",
        "X-forwarded-For",
        "X-Fowarded-For",
        "Zsa-Skip-Avscanning",
        "X-Forward-For",
        "X-Forwarded-",
        "X-OSSProxy",
        "X-ProxyUser-IP",
        "X-WrProxy-ID",
        "x-forwarded-for",
        "Forwarded",
        "Xroxy-Connection",
        "X-YouTube-Edu-Filter",
        "Proxy-Authorization"
        "X-FORWARDED-FOR",
        "X-WebsenseProxyChannel",
        "proxy-remote-user",
        "X-FB-Proxy",
        "Client-ip",
        "clientip",
        "X-Target-Proxy",
        "X-IMForwards",
        "X-Forward-Via",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-server",
        "host",  # browsers don't send lowercase headers but some proxies lowercase
        "connection",
        "X-OSSProxy",
        "via",
        "X-Server-IP",
        "Pxyro-Connection",  # citrix
        "Client-IP",
        "Squixa-Proxy",
        "X-If-Via",
        "Client-Ip",
        "X-MSISDN",
        "X-CYBERsitter-Content-Flag",
        "X-CYBERsitter-CSVT-Token",
        "X-Real-IP",
        "X-CLIENT-IP",
        "True-IP",
        "X-Forwarded-User"
    ])

    def check_invalid_headers(self, headers):
        return set(headers) & self.BAD_HEADERS

    def invalid_ec_point_formats(self, methods):
        if self.POINT_COMPRESSION_METHODS and methods:
            return methods != self.POINT_COMPRESSION_METHODS
        return None

    def check_invalid_curves(self, curves):
        if self.CURVES:
            set(curves) - set(self.CURVES)
        return None

    def loses_pfs(self, ciphers):
        if self.pfs:
            return not self.ciphercheck.is_first_pfs(ciphers)

    def invalid_compression_methods(self, compression):
        return compression != self.COMPRESSION_METHODS

    def get_security_level(self, version, ciphers):
        if type(version) in (str, unicode, int):
            version = self.convert_version(version)
        if version == self.VERSION_TLS_1_2 or version == self.VERSION_TLS_1_3:
            version_score = 1
        elif version == self.VERSION_TLS_1_1 or version == self.VERSION_TLS_1_0:
            version_score = 2
        elif version == self.VERSION_SSL_3:
            version_score = 3
        else:
            version_score = 4

        cipher_score = self.ciphercheck.get_security(ciphers)

        return max(version_score, cipher_score)

    def change_in_security(self, version, ciphers):
        if type(version) in (str, unicode, int):
            version = self.convert_version(version)
        if version == self.VERSION_TLS_1_2 or version == self.VERSION_TLS_1_3:
            version_score = 1
        elif version == self.VERSION_TLS_1_1 or version == self.VERSION_TLS_1_0:
            version_score = 2
        elif version == self.VERSION_SSL_3:
            version_score = 3
        else:
            version_score = 4

        cipher_score = self.ciphercheck.get_security(ciphers)

        return (self.security, max([version_score, cipher_score]))

    def check_blacklisted_ua(self, ua):
        if ua and "Dragon/" in ua:
            return True

    def fp(self, version, ciphers, extensions):
        v = str(version)
        ciphers = ",".join([str(cipher) for cipher in ciphers])
        extensions = ",".join([str(ext) for ext in extensions])
        to_h = "|".join([str(v), ciphers, extensions])
        return hashlib.sha1(to_h).hexdigest()

    def zfp(self, version, ciphers, extensions, curves, possible, mitm):
        if possible == self.POSSIBLE:
            return "s-OK"
        # if we know the software being used to MITM, just use that.
        if mitm:
            return "sw-%s" % mitm.replace(" ", "_")
        if self.check_valid_ciphers(ciphers) and self.check_valid_cipher_ordering(ciphers):
            ciphers = "DEFAULT"
        else:
            ciphers = ",".join([str(cipher) for cipher in ciphers])
        # let's ignore padding for now?
        if extensions and extensions[-1] == 21:
            extensions = extensions[:-1]
        v = str(version)
        if extensions:
            extensions = ",".join([str(ext) for ext in extensions])
        else:
            extensions = ""
        if curves:
            curves = ",".join([str(ext) for ext in curves])
        else:
            curves = ""
        to_h = "|".join([ciphers, extensions, curves])
        return "fp-" + possible + "-" + hashlib.sha1(to_h).hexdigest()[:8]

    @staticmethod
    def make_bro_fingerprint(ciphers, curves, extensions,
                             point_formats, fingerprint):
        return '[$client_ciphers=vector(%s), $client_curves=vector(%s), $extensions=vector(%s), $point_formats=vector(%s), name="%s"]' % (
            str(ciphers).lstrip("[").rstrip("]"),
            str(curves).lstrip("[").rstrip("]"),
            str(extensions).lstrip("[").rstrip("]"),
            str(point_formats).lstrip("[").rstrip("]"), fingerprint)

    def check(self, version, ciphers, extensions, headers, ec_point_formats,
              curves, compression=[], ua=None):
        fp = self.fp(version, ciphers, extensions)
        weak_cipher = self.cipher_check.check_any_trivially_broken(ciphers)
        invalid_cipher = self.check_valid_ciphers(ciphers)
        invalid_cipher_ordering = not self.check_valid_cipher_ordering(ciphers)
        invalid_extensions = self.check_valid_extensions(extensions)
        invalid_extension_ordering = not self.check_valid_extension_ordering(
            extensions)
        invalid_ec_point_formats = ec_point_formats and self.invalid_ec_point_formats(
            ec_point_formats)
        invalid_version = self.check_version(version)
        invalid_headers = self.check_invalid_headers(headers)
        missing_extensions = self.check_required_extensions(
            version, extensions)
        invalid_curves = curves and self.check_invalid_curves(curves)
        blacklisted_ua = self.check_blacklisted_ua(ua)
        if compression is not None:
            invalid_compression = self.invalid_compression_methods(compression)
        else:
            invalid_compression = None
        if invalid_extensions:
            valid = self.IMPOSSIBLE
            reason = "invalid_extension"
            reason_details = ",".join(
                map(lambda x: str(x), invalid_extensions))
        elif invalid_cipher:
            valid = self.IMPOSSIBLE
            reason = "invalid_cipher"
            reason_details = ",".join(map(lambda x: hex(x), invalid_cipher))
        elif invalid_extension_ordering:
            valid = self.IMPOSSIBLE
            reason = "invalid_extension_ordering"
            reason_details = ",".join(map(lambda x: str(x), extensions))
        elif invalid_version == self.IMPOSSIBLE:
            valid = self.IMPOSSIBLE
            reason = "invalid_version"
            reason_details = "%s not %s" % (
                version, self.get_version_name(self.DEFAULT_VERSION))
        elif invalid_cipher_ordering:
            valid = self.IMPOSSIBLE
            reason = "invalid_cipher_ordering"
            reason_details = ",".join(map(lambda x: hex(x), ciphers))
        elif invalid_compression:
            valid = self.IMPOSSIBLE
            reason = "invalid_compression"
            reason_details = ",".join(map(lambda x: str(x), compression or []))
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
        elif blacklisted_ua:
            valid = self.IMPOSSIBLE
            reason = "blacklisted_ua"
            reason_details = ""
        elif invalid_version == self.POSSIBLE and missing_extensions:
            valid = self.IMPOSSIBLE
            reason = "missing_extensions"
            reason_details = ",".join(
                map(lambda x: str(x), missing_extensions))
        elif invalid_version == self.UNLIKELY:
            valid = self.UNLIKELY
            reason = "unlikely_version"
            reason_details = "%s not %s" % (
                version, self.get_version_name(self.DEFAULT_VERSION))
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
            mitm, max_m_sec, mitm_type = self.db.get(self.convert_version(version), ciphers,
                                                     extensions, headers,
                                                     ec_point_formats, curves, ua, compression)
            if max_m_sec:
                new_sec = max(new_sec, max_m_sec)
        else:
            loses_pfs = old_sec = mitm = mitm_type = None
            new_sec = self.security
        zfp = self.zfp(version, ciphers, extensions, curves, valid, mitm)
        bro_fingerprint = self.make_bro_fingerprint(ciphers, curves, extensions,
                                                    ec_point_formats, zfp)
        return {
            "weak_ciphers": weak_cipher,
            "invalid_ciphers": invalid_cipher,
            "invalid_cipher_ordering": invalid_cipher_ordering,
            "invalid_extensions": invalid_extensions,
            "invalid_extension_ordering": invalid_extension_ordering,
            "invalid_headers": invalid_headers,
            "missing_extensions": missing_extensions,
            "version": invalid_version,
            "invalid_ec_point_formats": invalid_ec_point_formats,
            "point_formats": ec_point_formats,
            "invalid_curves": invalid_curves,
            "valid": valid,
            "reason": reason,
            "reason_details": reason_details,
            "old_sec": old_sec,
            "new_sec": new_sec,
            "loses_pfs": loses_pfs,
            "mitm": mitm,
            "mitm": mitm_type,
            "fp": fp,
            "zfp": zfp,
            "bro": bro_fingerprint
        }


class EmptyBrowser(BrowserVersion):
    CIPHERS = []
    EXTENSIONS = []
    REQUIRED_EXTENSIONS = []

