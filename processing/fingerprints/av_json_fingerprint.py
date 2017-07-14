from mitmengine.ciphers import *
from fingerprint import Fingerprint
import json

class AVJsonFingerprint(Fingerprint):

    TYPE = "antivirus"

    def get_extensions(self, data):
        extensions = [ext['type'] for ext in data['extensions']]

        return extensions if len(extensions) > 0 else None

    def get_ec_point_formats(self, data):
        for ext in data['extensions']:
            if ext['type'] == 11:
                return ext['data']['ec_point_formats']

        return []

    def get_elliptic_curves(self, data):
        for ext in data['extensions']:
            if ext['type'] == 10:
                return ext['data']['elliptic_curves']

        return []

    def convert_version(self, version):
        if not version:
            return None
        elif version == 0x0002:
            return Fingerprint.VERSION_SSL_2
        elif version == 0x0300:
            return Fingerprint.VERSION_SSL_3
        elif version == 0x0301:
            return Fingerprint.VERSION_TLS_1_0
        elif version == 0x0302:
            return Fingerprint.VERSION_TLS_1_1
        elif version == 0x0303:
            return Fingerprint.VERSION_TLS_1_2
        elif version == 0x0304:
            return Fingerprint.VERSION_TLS_1_3
        else:
            raise Exception("Unknown version: %s" % version)

    def __init__(self, filepath):
        #with open(filepath) as json_file:
        data = json.loads(filepath)
        self.VERSION = self.convert_version(data['data']['version'])
        self.CIPHERS = data['data']['cipher_suites']
        self.EXTENSIONS = self.get_extensions(data['data'])
        self.EC_POINT_FORMATS = self.get_ec_point_formats(data['data'])
        self.CURVES = self.get_elliptic_curves(data['data'])
        self.MAX_SECURITY = None

    @classmethod
    def create_custom_fingerprint(self, json_file):

        fingerprint_name = json.loads(json_file)['fingerprint'].encode('ascii')
        class CustomFingerprint(AVJsonFingerprint): pass
        CustomFingerprint.__name__ = fingerprint_name.replace("-", "_").title().replace("_","")

        return CustomFingerprint(json_file)


    def print_fp(self):
        print self.VERSION
        print self.CIPHERS
        print self.EXTENSIONS
        print self.EC_POINT_FORMATS
        print self.CURVES
