TLS Fingerprints
==========================

This repo contains TLS fingerprints documented in [The Security Impact of HTTPS
Interception](https://zakird.com/papers/https_interception.pdf).

[Raw](https://github.com/zakird/tlsfingerprints/tree/master/raw) contains PCAP
and p0f files of browsers and products we fingerprint.
[Processing](https://github.com/zakird/tlsfingerprints/tree/master/processing)
contains a subset of the Python code we used for processing data for the paper.

Note: these fingerprints were collected in early 2016. Browsers, antivirus
products, and middleboxes ahave likely changed cryptographic configuration since
this time. While this may be immediately apparent for versioned browsers like
Firefox and Chrome, these could manifest as false positives in IE and Safari.

