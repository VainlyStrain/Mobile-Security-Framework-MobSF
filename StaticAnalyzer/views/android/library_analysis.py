# -*- coding: utf_8 -*-
"""Module holding the functions for code analysis."""

import logging
import subprocess
from pathlib import Path

from django.conf import settings

from MobSF.utils import filename_from_path

from StaticAnalyzer.views.shared_func import (
    url_n_email_extract,
)
from StaticAnalyzer.views.sast_engine import (
    niap_scan,
    scan,
)

logger = logging.getLogger(__name__)


def library_analysis(app_dir, typ, manifest_file):
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
            lsOutput = "I am a placeholder for LibScout."  # libScout output will be in here
            lsParsed = parseScout(lsOutput)
        except Exception:
            logger.exception('Running LibScout Analysis')
            lsParsed = ""

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
        return {'libscout': {}, 'libid': {}}
    finally:
        logger.info('Finished Library Analysis')


def parseScout(results):
    """
    extract & categorize relevant output
    from LibScout.
    """
    return {}  # TODO: implement me


def parseID(results):
    """
    extract & categorize relevant output
    from LibID.
    """
    return {}  # TODO: implement me
