import csv
import sys

from useragent import *
from browsers import *


class UserAgentRouter(object):

    def __init__(self):
        self.firefox = Firefox()
        self.chrome = Chrome()
        self.ie = InternetExplorer()
        self.desktop_safari = Safari()
        self.mobile_safari = MobileSafari()
        self.silk = Silk()
        self.silk_accelerated = SilkAccelerated()
        self.android_browser = AndroidBrowser()

    def route(self, ua, raw_ua):
        if ua.browser == "firefox" or ua.browser == "firefox mobile":
            return self.firefox
        elif ua.browser in ("chrome", "chromium", "chrome mobile"):
            return self.chrome
        elif ua.browser == "ie" or ua.browser == "edge":
            return self.ie
        elif ua.browser == "safari":
            return self.desktop_safari
        elif ua.browser in ("mobile safari", "mobile safari uiwebview"):
            # This isn't rael safari, it's google search app
            if "GSA/" in raw_ua:
                return None
            return self.mobile_safari
        elif ua.browser == "amazon silk":
            if raw_ua and "Silk-Accelerated=true" in raw_ua:
                return self.silk_accelerated
            else:
                return self.silk
        elif ua.browser == "android":
            return self.android_browser


class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class Processor(object):

    def __init__(self):
        self.router = UserAgentRouter()
        self._total_statistics = {"total": 0, "impossible": 0, "unlikely": 0,
                                  "possible": 0, "weakciphers": 0}
        self._browser_statistics = {}
        self._os_statistics = {}
        self._csv = csv.writer(sys.stdout, quotechar="'")
        self._browser_version = EmptyBrowser()

    def update_statistics(self, os, os_version, browser, browser_version, count,
                          verdict, details):
        self._total_statistics[verdict.lower()] += count
        self._total_statistics["total"] += count
        if details["weak_ciphers"]:
            self._total_statistics["weakciphers"] += count

    def classify_debug(self, user_agent, version, ciphers,
                       extensions, headers, count):
        ua = UserAgent(user_agent)
        browser = self.router.route(ua, user_agent)
        if not browser:
            print "\t Unknown Browser"
            return
        bv = browser.get(ua.browser_version, ua.os, ua.os_version)
        print count, ua.browser, ua.browser_version, ua.os, ua.os_version
        if not bv:
            print "\t Unknown Version"
            return
        retv = bv.check(version, ciphers, extensions, headers, compression,
                        user_agent)
        print "\t Ciphers:", retv["invalid_ciphers"]
        print "\t Extensions:", retv["invalid_extensions"]
        print "\t Cipher Ordering:", retv["invalid_cipher_ordering"]
        print "\t Extension Ordering:", retv["invalid_extension_ordering"]
        print "\t Missing Extensions", retv["missing_extensions"]
        print "\t Version", retv["version"]
        print "\t Headers", retv["invalid_headers"]
        print "\t Verdict:",
        if retv["valid"] == "IMPOSSIBLE":
            print Colors.FAIL, retv["valid"], Colors.ENDC
        elif retv["valid"] == "UNLIKELY":
            print Colors.WARNING, retv["valid"], Colors.ENDC
        else:
            print Colors.OKGREEN, retv["valid"], Colors.ENDC
        if retv["reason"] != bv.POSSIBLE:
            print "\t Rationale", retv["reason"]
            print "\t Details", retv["reason_details"]
        self.update_statistics(ua.os, ua.os_version, ua.browser,
                               ua.browser_version, count, retv["valid"], retv)

    def print_csv_headers(self):
        self._csv.writerow(["count", "browser", "browser version", "OS", "OS version", "Status",
                            "Rationale", "Rationale Details", "User Agent", "TLS Version",
                            "ciphers", "extensions", "headers", "invalid ciphers",
                            "invalid extensions", "missing extensions", "invalid headers",
                            "version verdict", "invalid cipher ordering",
                            "invalid extension ordering", "invalid ec point formats",
                            "invalid curves", "oldsec", "newsec", "loses_pfs", "mitm", "fp", "zfp"])

    def check(self, user_agent, version, ciphers, extensions, headers,
              count, ec_point_formats=None, curves=None, override_ua=None,
              compression=None):
        if override_ua:
            ua = override_ua
        else:
            ua = UserAgent(user_agent)
        browser = self.router.route(ua, user_agent)
        if not browser:
            return {"status": "unknown_browser"}
        bv = browser.get(ua.browser_version, ua.os, ua.os_version)
        if not bv:
            return {"status": "unknown_version"}
        return bv.check(version, ciphers, extensions, headers,
                        ec_point_formats, curves, compression, user_agent)

    def classify_security(self, version, ciphers):
        return self._browser_version.get_security_level(version, ciphers)

    def classify_stats(self, user_agent, version, ciphers, extensions, headers,
                       count, ec_point_formats=None, curves=None, override_ua=None,
                       compression=None):

        if override_ua:
            ua = override_ua
        else:
            ua = UserAgent(user_agent)

        if ua.os == "Windows XP":
            return None

        status = None
        results = {}
        results["count"] = count
        results["ua"] = user_agent
        results["browser"] = ua.browser
        results["browser_version"] = ua.browser_version
        results["os"] = ua.os
        results["os_version"] = ua.os_version
        browser = self.router.route(ua, user_agent)

        if not browser:
            results["status"] = "unknown_browser"
            results["version"] = version
            results["ciphers"] = ciphers
            results["extensions"] = extensions
            results["curves"] = curves
            results["compression"] = compression
            results["ec_point_formats"] = ec_point_formats
            return results
        bv = browser.get(ua.browser_version, ua.os, ua.os_version)
        if not bv:
            results["status"] = "unknown_version"
            results["version"] = version
            results["ciphers"] = ciphers
            results["extensions"] = extensions
            results["curves"] = curves
            results["compression"] = compression
            results["ec_point_formats"] = ec_point_formats
            return results
        results = bv.check(version, ciphers, extensions, headers,
                           ec_point_formats, curves, compression, user_agent)
        results["status"] = results["valid"]
        results["count"] = count
        results["ua"] = user_agent
        results["ciphers"] = ciphers
        results["extensions"] = extensions
        results["headers"] = list(headers)
        results["browser"] = ua.browser
        results["browser_version"] = browser.pretty_version(ua.browser_version)
        results["os"] = ua.os
        results["os_version"] = ua.os_version
        results["invalid_ciphers"] = list(results["invalid_ciphers"])
        results["invalid_extensions"] = list(results["invalid_extensions"])
        results["invalid_curves"] = list(results["invalid_curves"]) if results[
            "invalid_curves"] else []
        results["missing_extensions"] = list(results["missing_extensions"])
        results["invalid_headers"] = list(results["invalid_headers"])
        results["unlikely_ciphers"] = list(results.get("unlikely_ciphers", []))
        return results

    def get_statistics(self):
        return self._total_statistics

processor = Processor()
