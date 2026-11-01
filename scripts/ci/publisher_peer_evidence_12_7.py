"""Immutable alpha.12.7 peer selection; validation lives in one shared implementation."""
from functools import partial
import publisher_peer_validation as _validation
from publisher_peer_validation import (
    CASES, DISPOSITION, JSON_LIMIT, require, digest, strict_json, scoped,
    members, cross_bind,
)

PATH = 'release/ci/publisher-peer-evidence-12.7.json'
VERSION = '1.15.0-polaris-alpha.12.7'
SOURCE = '3155c9151f553967aabcee93f09e51084fc89899'
RUN_ID = 40956987023
load = partial(_validation.load, path=PATH, expected_source=SOURCE, expected_version=VERSION, run_id=RUN_ID)
check_api = partial(_validation.check_api, expected_source=SOURCE)
summary = partial(_validation.summary, expected_source=SOURCE)
record = partial(_validation.record, path=PATH, summary=summary)
validate_receipt = partial(_validation.validate_receipt, expected_source=SOURCE, summary=summary)


def select(root, source, version, tag, tree=None, tag_object=None):
    return _validation.select(root, source, version, tag, tree, tag_object,
                              expected_source=SOURCE, expected_version=VERSION, load=load)


def mapping(root, role, artifact, relative, source):
    return _validation.mapping(root, role, artifact, relative, source, expected_source=SOURCE, load=load)


def check_inventory(root, actual, publisher):
    return _validation.check_inventory(root, actual, publisher, expected_source=SOURCE,
                                       expected_version=VERSION, select=select, record=record, summary=summary)
