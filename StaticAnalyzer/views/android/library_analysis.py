# -*- coding: utf_8 -*-
"""Module holding the functions for code analysis."""

import logging
import subprocess

from MobSF.settings import (
    LIBSCOUT_DIR,
    LIBSCOUT_PROFILES_DIR,
    SDK_PATH
)


logger = logging.getLogger(__name__)


def library_analysis(app_path):
    """Library Analysis Module.

    Perform vulnerability analysis on the
    app's libraries. Uses LibScout & LibID.
    """
    try:
        logger.info('Library Analysis Started')

        # start LibScout
        logger.info('Launching LibScout')

        try:
            ls_output = ''  # libScout output will be in here

            if SDK_PATH == '' or 'android.jar' not in SDK_PATH.lower():
                error = ('SDK Path not set or invalid. Make sure '
                         'SDK_PATH in "settings.py" points to android.jar.')
                
                raise ValueError(error)

            command = [
                'java', '-jar', 'build/libs/LibScout.jar',
                '-a', SDK_PATH, '-p', LIBSCOUT_PROFILES_DIR,
                '-o', 'match', app_path,
            ]

            process = subprocess.run(
                command,
                capture_output=True,
                cwd=LIBSCOUT_DIR,
                check=True,
                encoding='utf-8'
            )

            ls_output = process.stdout
            ls_parsed = parse_scout(ls_output)
        except Exception:
            logger.exception('Running LibScout Analysis')
            ls_parsed = []

        logger.info('Launching LibID')

        # TODO
        try:
            lid_output = 'I am a placeholder for LibID.'
            lid_parsed = parse_id(lid_output)
        except Exception:
            logger.exception('Running LibID Analysis')
            lid_parsed = ''

        return {'libscout': ls_parsed, 'libid': lid_parsed}
    except Exception:
        logger.exception('Performing Library Analysis')
        return {'libscout': [], 'libid': {}}
    finally:
        logger.info('Finished Library Analysis')


def parse_scout(lsout):
    """Parse the output of LibScout.

    Return list containing relevant output
    for each finding.
    """
    results = lsout.split('Full library matches:')[1]
    full_match = results.split('Partial library matches:')[0]
    partial_match = results.split('Partial library matches:')[1]

    libs = full_match.split('name:') + partial_match.split('name:')
    profiles = parse_scout_subroutine(libs)

    return profiles


def parse_scout_subroutine(libs):
    profiles = []
    for library in libs:
        # skip output not matching to a library
        if 'category' not in library:
            continue

        # initialize accuracy - will reduce if only partial match
        accuracy = '1.0'

        # parse the profile fields
        name = library.split('\n')[0].strip()
        category = library.split('category:')[1].split('\n')[0].strip()
        version_info = library.split('version:')[1].split('\n')[0]
        version = version_info.split('[')[0].strip()
        old = True if 'OLD VERSION' in version_info else False
        date = library.split('release-date:')[1].split('\n')[0].strip()
        root = ''
        if 'lib root package:' in library:
            root = library.split('root package:')[1].split('\n')[0].strip()
        comment = ''
        if 'comment:' in library:
            comment = library.split('comment:')[1].split('\n')[0].strip()
        vulnerable = True if '[SECURITY]' in comment else False
        if 'score:' in library:
            accuracy = library.split('score:')[1].split('\n')[0].strip()
        vuln = comment if vulnerable else ''
        profile = {
            'name': name,
            'category': category,
            'version': version,
            'releaseDate': date,
            'rootPkg': root,
            'deprecated': old,
            'vulnerable': vulnerable,
            'vulnerabilities': [vuln],
            'certainty': accuracy,
        }
        profiles.append(profile)
    return profiles


def parse_id(results):
    """Parse the output of LibID."""
    return {}  # TODO: implement me
