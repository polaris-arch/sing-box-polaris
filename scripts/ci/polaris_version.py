#!/usr/bin/env python3
"""Canonical Polaris identity; package-manager spellings never replace the raw version."""
import re

NUMBER = r'(?:0|[1-9][0-9]*)'
CORE = rf'{NUMBER}\.{NUMBER}\.{NUMBER}'
CHANNEL = r'(?:alpha|beta|rc)'
PATTERN = rf'{CORE}-polaris-{CHANNEL}\.{NUMBER}(?:\.{NUMBER})?'


def validate(value):
    """Accept one optional Polaris patch, not another upstream prerelease number."""
    if not isinstance(value, str) or not re.fullmatch(PATTERN, value):
        raise ValueError('expected MAJOR.MINOR.PATCH-polaris-{alpha,beta,rc}.NUMBER[.PATCH] (canonical decimal numbers)')
    return value
