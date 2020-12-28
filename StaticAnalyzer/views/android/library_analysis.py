# -*- coding: utf_8 -*-
"""Module holding the functions for code analysis."""

import logging
import subprocess
from pathlib import Path

from django.conf import settings

from MobSF.utils import filename_from_path

from settings import LIBSCOUT_DIR, LIBSCOUT_PROFILES_DIR, SDK_PATH

from StaticAnalyzer.views.shared_func import (
    url_n_email_extract,
)
from StaticAnalyzer.views.sast_engine import (
    niap_scan,
    scan,
)

logger = logging.getLogger(__name__)


def library_analysis(app_path):
    """
    Perform vulnerability analysis on the
    app's libraries.
    """
    try:
        logger.info('Library Analysis Started')
        """
        libToolsRoot = ""  # TODO: fill me out
        libScoutPath = libToolsRoot / "LibScout"
        libScoutProfilesPath = libToolsRoot / ""  # TODO: fill me out
        libIDPath = libToolsRoot / ""  # TODO: fill me out
        """

        # start LibScout
        logger.info('Launching LibScout')

        # TODO
        try:
            lsOutput = ""  # libScout output will be in here

            if SDK_PATH == "" or "android.jar" not in SDK_PATH.lower():
                raise Exception("
                    SDK Path not set or invalid. Make sure SDK_PATH in 'settings.py' points to android.jar.
                ")

            command = [
                "java", "-jar", "LibScout.jar",
                "-a", SDK_PATH, "-p", LIBSCOUT_PROFILES_DIR,
                "-o", "match", app_path
            ]

            process = subprocess.run(command, capture_output=True, cwd=LIBSCOUT_DIR, check=True, encoding="utf-8")
            lsOutput = process.stdout
            lsParsed = parseScout(lsOutput)
        except Exception:
            logger.exception('Running LibScout Analysis')
            lsParsed = []

        logger.info('Launching LibID')

        # TODO
        try:
            lidOutput = "I am a placeholder for LibID."  # libID output will be in here
            lidParsed = parseID(lidOutput)
        except Exception:
            logger.exception('Running LibID Analysis')
            lidParsed = ""

        return {'libscout': lsParsed, 'libid': lidParsed}
    except Exception:
        logger.exception('Performing Library Analysis')
        return {'libscout': [], 'libid': {}}
    finally:
        logger.info('Finished Library Analysis')


def parseScout(lsout):
    """
    extract & categorize relevant output
    from LibScout.
    """
    results = lsout.split("Full library matches:")[1]
    fullMatch = results.split("Partial library matches:")[0]
    partialMatch = results.split("Partial library matches:")[1]

    libList = fullMatch.split("name:") + partialMatch.split("name:")
    profiles = parseScoutSubroutine(libList)

    return profiles


def parseScoutSubroutine(libList):
    profiles = []
    for library in libList:
        # skip output not matching to a library
        if not "category" in library:
            continue

        # initialize accuracy - will reduce if only partial match
        accuracy = "1.0"

        # parse the profile fields
        name = library.split("\n")[0].strip()
        category = library.split("category:")[1].split("\n")[0].strip()
        versionInfo = library.split("version:")[1].split("\n")[0]
        version = versionInfo.split("[")[0].strip()
        old = True if "OLD VERSION" in versionInfo else False
        releaseDate = library.split("release-date:")[1].split("\n")[0].strip()
        rootPkg = library.split("lib root package:")[1].split("\n")[0].strip() if "lib root package:" in library else ""
        comment = library.split("comment:")[1].split("\n")[0].strip() if "comment:" in library else ""
        vulnerable = True if "[SECURITY]" in comment else False
        if "score:" in library:
            accuracy = library.split("score:")[1].split("\n")[0].strip()
        vuln = comment if vulnerable else ""
        profile = {
            "name": name,
            "category": category,
            "version": version,
            "releaseDate": releaseDate,
            "rootPkg": rootPkg,
            "deprecated": old,
            "vulnerable": vulnerable,
            "vulnerabilities": [vuln],
            "certainty": accuracy
        }
        profiles.append(profile)
    return profiles


def parseID(results):
    """
    extract & categorize relevant output
    from LibID.
    """
    return {}  # TODO: implement me
