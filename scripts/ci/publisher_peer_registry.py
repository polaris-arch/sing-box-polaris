"""Two immutable peer selections; neither evidence artifact is a public asset."""
import publisher_peer_evidence as previous
import publisher_peer_evidence_12_5 as current

MODULES = (previous, current)
JSON_LIMIT = previous.JSON_LIMIT
strict_json = previous.strict_json


def _identity(source, version, tag):
    matches = [m for m in MODULES if source == m.SOURCE or version == m.VERSION or tag == 'v' + m.VERSION]
    previous.require(len(matches) <= 1, 'mixed historical/current selection identity')
    if not matches:
        return None
    m = matches[0]
    previous.require((source, version, tag) == (m.SOURCE, m.VERSION, 'v' + m.VERSION), 'partial selection identity')
    return m


def _module(policy):
    previous.require(type(policy) is dict and type(policy.get('selection')) is dict, 'invalid registry policy')
    s = policy['selection']
    m = _identity(s.get('sourceCommit'), s.get('version'), s.get('tag'))
    previous.require(m is not None, 'unregistered peer policy')
    return m


def select(root, source, version, tag, tree=None, tag_object=None):
    m = _identity(source, version, tag)
    return None if m is None else m.select(root, source, version, tag, tree, tag_object)


def scoped(scope, policy, runs):
    return scope if policy is None else _module(policy).scoped(scope, policy, runs)


def mapping(root, role, artifact, relative, source):
    for m in MODULES:
        if artifact == 'native-controlled-peer-' + m.SOURCE:
            return m.mapping(root, role, artifact, relative, source)
    return None


def check_api(policy, role, run, artifact):
    return _module(policy).check_api(policy, role, run, artifact)


def members(policy, items):
    return _module(policy).members(policy, items)


def validate_receipt(policy, measured, receipt):
    return _module(policy).validate_receipt(policy, measured, receipt)


def cross_bind(policy, index, index_sha, all_entry):
    return _module(policy).cross_bind(policy, index, index_sha, all_entry)


def record(policy, publisher):
    return _module(policy).record(policy, publisher)


def check_inventory(root, actual, publisher):
    m = _identity(actual['sourceCommit'], actual.get('version'), actual.get('tag'))
    if m is None:
        previous.require('controlledPeerEvidence' not in actual, 'unregistered inventory peer evidence')
        return
    # The selected module reloads the exact file and compares source, tree, tag,
    # publisher, policy hash, API identity and nonpublic member mapping together.
    return m.check_inventory(root, actual, publisher)
