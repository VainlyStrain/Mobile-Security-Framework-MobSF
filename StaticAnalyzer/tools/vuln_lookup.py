# -*- coding: utf_8 -*-
"""Look up vulnerable library versions."""

import logging

from packaging.version import parse

"""Map library name & version to CVE.

Inner lists: [<INTRODUCED>, <FIXED>]
"""
vuln_db = {
    'Airpush': {
        'AIRPUSH_01': [
            ['NA', '8.1'],
        ],
    },
    'Apache CC': {
        'CVE-2015-6420': [
            ['3.2.1', '3.2.2'],
            ['4.0', '4.1'],
        ],
    },
    'Dropbox': {
        'CVE-2014-8889': [
            ['1.5.4', '1.6.2'],
        ],
    },
    'Facebook': {
        'FB_01': [
            ['3.15', '3.16'],
        ],
    },
    'MoPub': {
        'MOPUB_01': [
            ['NA', '4.4.0'],
        ],
    },
    'OkHttp': {
        'CVE-2016-2402': [
            ['2.1', '2.7.5'],
            ['3.0.0', '3.2.0'],
        ],
    },
    'Plexus Archiver': {
        'PLA_01': [
            ['NA', '3.6.0'],
        ],
    },
    'SuperSonic': {
        'SUSO_01': [
            ['NA', '6.3.5'],
        ],
    },
    'Vungle': {
        'VUNGLE_01': [
            ['NA', '3.3.0'],
        ],
    },
    'ZeroTurnaround': {
        'ZT_01': [
            ['NA', '1.13'],
        ],
    },
}


"""Map CVE to Description."""
description_map = {
    'AIRPUSH_01': ('Unsanitized default WebView settings '
                   '(https://support.google.com/faqs/answer/6376737)'),
    'CVE-2015-6420': ('Deserialization vulnerability '
                      '(https://www.kb.cert.org/vuls/id/576313)'),
    'CVE-2014-8889': ('DroppedIn vulnerability '
                      '(https://www.cvedetails.com/cve/CVE-2014-8889)'),
    'FB_01': ('Account hijacking vulnerability (https://thehacker'
              'news.com/2014/07/facebook-sdk-vulnerability-puts.html)'),
    'MOPUB_01': ('Unsanitized default WebView settings '
                 '(https://support.google.com/faqs/answer/6345928)'),
    'CVE-2016-2402': ('Certificate pinning bypass (https://cve.mitr'
                      'e.org/cgi-bin/cvename.cgi?name=CVE-2016-2402)'),
    'PLA_01': ('Zip Slip vulnerability '
               '(https://github.com/snyk/zip-slip-vulnerability)'),
    'SUSO_01': ('Unsafe functionality exposure via JS '
                '(https://support.google.com/faqs/answer/7126517)'),
    'VUNGLE_01': ('MitM attack vulnerability '
                  '(https://support.google.com/faqs/answer/6313713)'),
    'ZT_01': ('Zip Slip vulnerability '
              '(https://github.com/snyk/zip-slip-vulnerability)'),
}


logger = logging.getLogger(__name__)


def contains_version(version_range, version):
    """Checks if version is in specific range."""
    check = False
    try:
        lib_version = parse(version)
        intro = version_range[0]
        if intro == "NA":
            intro = "0"
        start = parse(intro)
        fix = parse(version_range[1])
        check = lib_version >= start and lib_version < fix
    except Exception:
        logger.exception('Comparing Versions')
    return check


def is_vulnerable(name, version):
    """Checks if library version has known vulnerability."""
    vulnerable = False
    vulnerabilities = []
    if name not in vuln_db:
        return (vulnerable, [''])
    for candidate, version_ranges in vuln_db[name].items():
        for version_range in version_ranges:
            if contains_version(version_range, version):
                vulnerable = True
                description = '{} - {}'.format(
                    candidate, description_map[candidate],
                )
                vulnerabilities.append(description)
    if not vulnerable:
        vulnerabilities = ['']
    return (vulnerable, vulnerabilities)
