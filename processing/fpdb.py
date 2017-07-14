import os.path
from fingerprints import *
import glob

import fingerprints.av_fingerprints.json_fingerprints
import fingerprints.misc_fingerprints.json_fingerprints

class FingerprintDatabase(object):

    FINGERPRINTS = [
        CiscoWSAClientHello,
        BlueCoat,
        BlueCoatFingerprint,
        CyberSitterHeader,
        ForcePoint,
        AdGuard,
        AvastMac,
        Avast,
        AVG,
        BitDefender,
        CyberSitter,
        DrWeb10_2016,
        DrWeb10_2015,
        ESET,
        GData,
        Kaspersky,
        Kindergate,
        Netnanny7260,
        Netnanny7261,
        PCPandora,
        PCPandora7_0_22,
        Barracuda,
        ESET20160204,
        Kaspersky20150204,
        Chromodo,
        Citrix,
        MicrosoftTMG,
        BullGuard,
        WebTitan,
        BitDefender20150204,
        BullGuard16_0_314_4,
        KomodiaSuperFish,
        Qustodio_20160213,
        PrivDog_3_0_96_0,
        PrivDog_4_0_27,
        Sophos,
        Untangle_11_2_1,
        Untangle_12_0_0,
        FP_32af0048eb5cb04fe60b2cc7ecff97941320f07d4e53bd00c8d48cdf3418defe,
        FP_3a9698bc7a76c09f8c8eb0d85e848c6d275f23ef719b77b26d9a2934643b1394,
        FP_2506fff93ea83840cd733f3a7c0526041d1ccaab1ffda2740fe986865d8a7bd5,
        FP_e44c49fd6b181b0ecd1b8d04092c94746f1d912a96e369ab11f02416936ace0b,
        Wajam_97e8f6b46de9e1e3e312de78ed90e17f,
        Fortigate,
        JuniperSRXDefault,
        JuniperSRXStrong,
        JuniperSRXWeak,
        HideMyIP,
        KeepMyFamilySecure,
        StaffCop,
        BlueCoatNoAgent
    ]

    AV_VENDORS = [
        "Avast",
        "AVG",
        "Barracuda",
        "BitDefender",
        "BlueCoat",
        "BullGuard",
        "Chromodo",
        "CiscoWS",
        "Citrix",
        "CyberSitter",
        "DrWeb",
        "ESET",
        "ForcePoint",
        "Fortigate",
        "GData",
        "HideMyIP",
        "JuniperSRX",
        "Kaspersky",
        "KeepMyFamilySecure",
        "HideMyIP",
        "Kindergate",
        "KomodiaSuperFish",
        "MicrosoftTMG",
        "Netnanny",
        "PCPandora",
        "PrivDog",
        "Qustodio",
        "Sophos",
        "StaffCop",
        "Untangle",
        "Wajam",
        "WebTitan",
        "AdGuard",
    ]

    def __init__(self):
        self.fingerprints = map(lambda x: x(), self.FINGERPRINTS)
        av = []
        for f in fingerprints.av_fingerprints.json_fingerprints.json_fingerprints:
            av.append(AVJsonFingerprint.create_custom_fingerprint(f))
        if not av:
            raise Exception("No AV JSON fingerprints found")
        self.fingerprints.extend(av)

        misc = []
        for f in fingerprints.misc_fingerprints.json_fingerprints.json_fingerprints:
            misc.append(MiscJsonFingerprint.create_custom_fingerprint(f))
        if not misc:
            raise Exception("No misc JSON fingerprints found")
        self.fingerprints.extend(misc)

    def get(self, *args, **kwargs):
        for fingerprint in self.fingerprints:
            match, max_sec = fingerprint.match(*args, **kwargs)
            if match:
                fp_name = fingerprint.__class__.__name__
                for vendor in self.AV_VENDORS:
                    if vendor.lower() in fp_name.lower():
                        fp_name = vendor
                        break
                return fp_name, max_sec, fingerprint.TYPE
        else:
            return None, None, None

