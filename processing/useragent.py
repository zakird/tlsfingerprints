import sys
import user_agents


class UserAgent(object):

    def __init__(self, ua):
        self.raw_ua = ua
        self.parsed = user_agents.parse(ua)

    @property
    def os(self):
        return self.parsed.os.family

    @property
    def os_version(self):
        return self.parsed.os.version

    @property
    def browser(self):
        return self.parsed.browser.family.lower()

    @property
    def browser_version(self):
        return self.parsed.browser.version


class OverrideUserAgent(object):
    def __init__(self,
            os,
            os_version,
            browser,
            browser_version):
        self.os = os
        self.os_version = os_version
        self.browser = browser
        self.browser_version = browser_version
