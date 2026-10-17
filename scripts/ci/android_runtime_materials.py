"""Validate resolution evidence without running Gradle or application code."""
import re

def validate(record, expected_configuration):
    if not isinstance(record, dict) or record.get('schema') != 'polaris-android-runtime-materials-v1':
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
    seen = set()
    for a in artifacts:
        if not isinstance(a, dict) or a.get('module') not in modules:
            raise ValueError('Android artifact has no resolved component')
        name = a.get('name')
        if not isinstance(name, str) or not name or '/' in name or '\\' in name or name in ('.', '..'):
            raise ValueError('invalid Android artifact name')
        key = (a['module'], name)
        if key in seen: raise ValueError('duplicate Android runtime artifact')
        seen.add(key)
        if type(a.get('bytes')) is not int or a['bytes'] <= 0 or not isinstance(a.get('sha256'), str) or not re.fullmatch('[0-9a-f]{64}', a['sha256']):
            raise ValueError('invalid Android artifact byte identity')
    return record
