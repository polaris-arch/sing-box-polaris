"""Validate resolution evidence without running Gradle or application code."""
import hashlib
import json
import re
from pathlib import Path

def validate(record, expected_configuration):
    if not isinstance(record, dict) or record.get('schema') != 'polaris-android-runtime-materials-v2':
        raise ValueError('invalid Android runtime material schema')
    if expected_configuration not in ('otherReleaseRuntimeClasspath', 'otherLegacyReleaseRuntimeClasspath') or record.get('configuration') != expected_configuration:
        raise ValueError('Android runtime configuration mismatch')
    components = record.get('components')
    artifacts = record.get('artifacts')
    if not isinstance(components, list) or not components or not isinstance(artifacts, list) or not artifacts:
        raise ValueError('empty Android resolved runtime evidence')
    if any(not isinstance(c, dict) or not isinstance(c.get('id'), str) or not c['id'] for c in components):
        raise ValueError('invalid Android resolved component')
    modules = {c.get('module') for c in components if isinstance(c.get('module'), str)}
    seen = {}
    normalized = []
    for a in artifacts:
        if not isinstance(a, dict) or a.get('module') not in modules:
            raise ValueError('Android artifact has no resolved component')
        name = a.get('name')
        if not isinstance(name, str) or not name or '/' in name or '\\' in name or name in ('.', '..'):
            raise ValueError('invalid Android artifact name')
        for field in ('artifactIdentity', 'artifactName', 'type'):
            if not isinstance(a.get(field), str) or not a[field]:
                raise ValueError('missing Android artifact identity field: ' + field)
        for field in ('extension', 'classifier'):
            if field not in a or (a[field] is not None and not isinstance(a[field], str)):
                raise ValueError('invalid Android artifact identity field: ' + field)
        variants = a.get('componentSelectedVariants')
        if not isinstance(variants, list) or not variants:
            raise ValueError('missing Android selected component variants')
        for v in variants:
            if not isinstance(v, dict) or any(not isinstance(v.get(k), str) or not v[k] for k in ('owner', 'name')):
                raise ValueError('invalid Android selected variant identity')
            if not isinstance(v.get('attributes'), dict) or any(not isinstance(k, str) or not isinstance(value, str) for k, value in v['attributes'].items()):
                raise ValueError('invalid Android selected variant attributes')
            if not isinstance(v.get('capabilities'), list) or any(not isinstance(cap, str) for cap in v['capabilities']):
                raise ValueError('invalid Android selected variant capabilities')
        identity = {k: a[k] for k in ('module', 'name', 'artifactIdentity', 'artifactName', 'type', 'extension', 'classifier')}
        identity['componentSelectedVariants'] = sorted(variants, key=lambda v: json.dumps(v, sort_keys=True))
        key = json.dumps(identity, sort_keys=True, separators=(',', ':'))
        if type(a.get('bytes')) is not int or a['bytes'] <= 0 or not isinstance(a.get('sha256'), str) or not re.fullmatch('[0-9a-f]{64}', a['sha256']):
            raise ValueError('invalid Android artifact byte identity')
        byte_identity = (a['bytes'], a['sha256'])
        if key in seen:
            if seen[key] != byte_identity:
                raise ValueError('conflicting Android runtime artifact byte identity')
            continue
        seen[key] = byte_identity
        normalized.append(a)
    return dict(record, artifacts=normalized, deduplicatedArtifactCount=len(artifacts)-len(normalized))


def write_diagnostic(root, metadata, client_source=None):
    """Persist bounded diagnostics even when validation fails; never copy exception text."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    records, errors = {}, {}
    for variant in ('other', 'otherLegacy'):
        path = root / (variant + '.json')
        item = {}
        try:
            raw = path.read_bytes()
            item['sha256'] = hashlib.sha256(raw).hexdigest()
            item['resolved'] = validate(json.loads(raw), variant + 'ReleaseRuntimeClasspath')
        except Exception as error:
            errors[variant] = type(error).__name__
            item['validationFailed'] = True
        records[variant] = item
    if client_source is None:
        errors['clientSource'] = 'unavailable'
    receipt = dict(metadata, schema='polaris-android-resolution-diagnostic-v2',
                   publicationEligible=False, clientSource=client_source, variants=records)
    (root / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    (root / 'diagnostics.json').write_text(json.dumps({'success': not errors, 'errors': errors}, indent=2) + '\n')
    return not errors

