"""Exact dfb1 OCI selection: 241 shared packages, two measured recipe deltas."""
import io
import re
import tarfile

from release_identity import same_identity
import oci_material_supplement as legacy
import oci_material_selection_12_7 as previous
from oci_material_reassociation import OCIReassociation, _image_identity

SOURCE = 'dfb1fc278c22ff73b833f12b986c0e499238e535'
TREE = '8ea894e795393cb4cddef57578733f1256200da1'
TAG = 'v1.15.0-polaris-alpha.12.9'
TAG_OBJECT = 'bac0f17b4bf9ba073996b4ac98f3707fca89a3da'
RUN_ID = 41379223932
ATTEMPT = 1
DIRECTORY = 'release/dependency-sources/oci/selections/41379223932-attempt1'
SELECTOR_BYTES = 13250
SELECTOR_SHA256 = 'ad6a719e9659146343e8639d1cce89656c74808aa8ce72d11c4bcd1039106b40'
SCHEMA = 'polaris-exact-oci-material-delta-12.9-policy-v1'
_require = legacy._require
_IMAGE_FIELDS = {'artifactId', 'archiveBytes', 'archiveSHA256', 'artifactAPIDigest', 'coreBytes',
                 'coreSHA256', 'imageBytes', 'imageSHA256', 'imageManifest', 'installedSHA256', 'platform'}
_DELTA_PACKAGES = [
    {'P': 'nftables', 'V': '1.1.7-r1', 'A': 'loongarch64', 'L': 'GPL-2.0-or-later', 'o': 'nftables',
     'c': '174f6ef6c7401e77351c7b14e556a9513876403e', 'C': 'Q1Rf5oNWbxU9oeuXAuQc4j4pfV1+Y='},
    {'P': 'tzdata', 'V': '2026f-r0', 'A': 'loongarch64', 'L': 'Public-Domain', 'o': 'tzdata',
     'c': '99b2eee03e7395355bbab078555618a88b3c47b9', 'C': 'Q1JzZRnBPEGt14rIQs6bAQ1KB6/0g='},
]
_LOONG_BASE = [{'uri': 'pkg:docker/ghcr.io/loong64/alpine@edge?platform=linux%2Floong64',
                'digest': {'sha256': '3946d87d1cfb4caab9b49d0f3412030360247b252e218294c50e35d0876d3f17'}}]
_RECIPE_TREES = {'nftables': '585ae370351dafdc0c16356088e1180f28639525',
                 'tzdata': '8152e72979a93582fa93b8a43fd0ad6dc5e6f230'}
_NEW_SOURCES = {
    'tzcode2026f.tar.gz': (329832, '5a18da01393679ef2559214dc687563f7f3d05691f6f58b7fbc0166f3e796cd6',
                         'eefcea60c37857214e1eba768d1bbd096de2a8f5afc9a776555552922cc174b32892d7442097b699b77efcba4d85649ed7d13e752ffdbcaad1050749c6c7b5aa'),
    'tzdata2026f.tar.gz': (483310, '01b4a91cec5167ed48c11e8ab78f2048cead78ce94b0cafcad0ae8c5a3044d3d',
                         '26189803c8b3e903dcc467404e2feefb7d190cb1870249a23577ce31e9dcbf187e4704e0b45c8d1366d1c501bb5b53a2e80f8e2828b2163be15e532f6acab52d'),
}


def _git_directory(files, prefix):
    """Recompute Git trees from exact reviewed file bytes, never run a recipe."""
    entries = {}
    for record, raw in files:
        path = legacy._relative(record['path']).as_posix()
        _require(path.startswith(prefix + '/'), 'dfb1 recipe file outside exact origin/commit')
        parts = path.removeprefix(prefix + '/').split('/')
        cursor = entries
        for part in parts[:-1]:
            _require(not isinstance(cursor.get(part), tuple), 'dfb1 recipe path collision')
            cursor = cursor.setdefault(part, {})
        _require(parts[-1] not in cursor, 'dfb1 duplicate recipe file')
        _require(record['gitMode'] in ('100644', '100755') and type(record['gitBlob']) is str,
                 'dfb1 recipe Git file mode/type')
        blob = legacy._sha(b'blob ' + str(len(raw)).encode() + b'\0' + raw, 'sha1')
        _require(blob == record['gitBlob'], 'dfb1 recipe Git blob differs')
        cursor[parts[-1]] = (record['gitMode'], blob)
    def tree(children):
        rows = []
        for name, value in children.items():
            mode, digest = ('40000', tree(value)) if isinstance(value, dict) else value
            rows.append((name + ('/' if mode == '40000' else ''), mode, digest, name))
        body = b''.join(mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(digest)
                        for _, mode, digest, name in sorted(rows))
        return legacy._sha(b'tree ' + str(len(body)).encode() + b'\0' + body, 'sha1')
    return tree(entries)


class _MaterialDelta(OCIReassociation):
    def _selection_schema(self):
        return 'polaris-exact-oci-material-delta-selection-v1'

    def _association_counts(self):
        return {'sharedPackageAssociationCount': 241, 'newPackageAssociationCount': 2,
                'crossArchitectureSourceAssociationCount': 0, 'newRecipeCount': 2,
                'changedBaseDependencyCount': 1}

    def _reassociation(self, root, selector, reference, material_map, historical, historical_root, historical_map):
        _require(type(reference) is dict and set(reference) == {
            'schema', 'sourceCommit', 'producerRunId', 'producerAttempt', 'legalConclusion',
            'materialMapSHA256', 'artifacts'}, 'dfb1 reference fields differ')
        _require(type(material_map) is dict and set(material_map) == {
            'schema', 'sourceCommit', 'producerRunId', 'producerAttempt', 'legalConclusion', 'sharedMaterials',
            'packageAssociationCount', 'newRecipeCount', 'exactPackageAssociations', 'newPackageAssociations',
            'crossArchitectureSourceAssociations', 'baseDependencyChanges', 'newRecipes'}, 'dfb1 material map fields differ')
        _require(reference['schema'] == 'polaris-current-oci-material-reference-v1'
                 and material_map['schema'] == 'polaris-exact-oci-material-delta-v1'
                 and same_identity(reference['materialMapSHA256'], selector['materialMap']['sha256']), 'dfb1 reference/map identity differs')
        for document in (reference, material_map):
            _require(same_identity((document['sourceCommit'], document['producerRunId'], document['producerAttempt']),
                                  (SOURCE, RUN_ID, ATTEMPT)) and document['legalConclusion'] is False,
                     'dfb1 material source/run/attempt identity differs')
        _require(same_identity(material_map['sharedMaterials'], selector['sharedMaterials'])
                 and same_identity(material_map['packageAssociationCount'], 243)
                 and same_identity(material_map['newRecipeCount'], 2)
                 and same_identity(material_map['crossArchitectureSourceAssociations'], []), 'dfb1 material ownership/count differs')
        _require(type(reference['artifacts']) is dict and set(reference['artifacts']) == legacy.ARTIFACT_NAMES,
                 'dfb1 requires exact nine OCI profiles')
        shared, changed, bases = [], [], []
        expected_changed = [{'artifact': 'oci-linux-loong64', 'package': package} for package in _DELTA_PACKAGES]
        for name, row in sorted(reference['artifacts'].items()):
            old = historical['artifacts'][name]
            _require(type(row) is dict and set(row) == _IMAGE_FIELDS | {'baseDependencies', 'repositories', 'packages'},
                     'dfb1 complete profile fields differ')
            image = {key: row[key] for key in _IMAGE_FIELDS}; _image_identity(image)
            _require(same_identity(image, selector['artifacts'][name])
                     and same_identity(row['platform'], old['platform'])
                     and same_identity(row['repositories'], old['repositories']), 'dfb1 image/platform/repository differs')
            expected_base = _LOONG_BASE if name == 'oci-linux-loong64' else old['baseDependencies']
            _require(same_identity(row['baseDependencies'], expected_base), 'dfb1 unexpected base dependency')
            if not same_identity(row['baseDependencies'], old['baseDependencies']):
                bases.append({'artifact': name, 'previous': old['baseDependencies'], 'actual': row['baseDependencies']})
            packages = row['packages']
            _require(type(packages) is list and len(packages) == 27, 'dfb1 package scope differs')
            for package in packages:
                legacy._package(package)
            _require(len({p['P'] for p in packages}) == 27
                     and same_identity(packages, sorted(packages, key=lambda p: (p['P'], p['V'], p['A']))), 'dfb1 package uniqueness/order differs')
            for package in packages:
                association = {'artifact': name, 'package': package}
                if any(same_identity(package, old_package) for old_package in old['packages']):
                    shared.append(association)
                else:
                    changed.append(association)
        _require(len(shared) == 241 and same_identity(changed, expected_changed)
                 and same_identity(material_map['exactPackageAssociations'], shared)
                 and same_identity(material_map['newPackageAssociations'], changed)
                 and len(bases) == 1 and same_identity(material_map['baseDependencyChanges'], bases), 'dfb1 exact 241+2/base association closure differs')
        self._delta_materials(root, selector, material_map)
        return reference

    def _delta_materials(self, root, selector, material_map):
        publisher_root = root
        for _ in legacy._relative(DIRECTORY).parts:
            publisher_root = publisher_root.parent
        _require(legacy._path(publisher_root, DIRECTORY) == root, 'dfb1 material root differs')
        recipes = material_map['newRecipes']
        _require(type(recipes) is list and len(recipes) == 2, 'dfb1 exact two recipe closures required')
        for recipe, package in zip(recipes, _DELTA_PACKAGES):
            _require(same_identity((recipe['repository'], recipe['repositoryHost'], recipe['projectId'],
                                   recipe['commit'], recipe['origin'], recipe['directoryTreeSHA']),
                                  ('alpine/aports', 'gitlab.alpinelinux.org', 1, package['c'], package['o'],
                                   _RECIPE_TREES[package['o']])), 'dfb1 official recipe origin/commit differs')
            files = recipe['files']
            _require(type(files) is list and 1 <= len(files) <= 64, 'dfb1 recipe directory member bound')
            prefix = 'aports/' + package['c'] + '/main/' + package['o']
            measured = []
            for row in files:
                # A logical member of this new Git tree can reuse exact bytes
                # from its immutable historical owner without copying a patch.
                raw = (legacy._file(publisher_root, row['historicalFile'], read=True) if 'historicalFile' in row
                       else legacy._file(root, row, read=True))
                _require(same_identity((len(raw), legacy._sha(raw)), (row['bytes'], row['sha256'])),
                         'dfb1 recipe member byte identity differs')
                measured.append((row, raw))
            _require(_git_directory(measured, prefix) == recipe['directoryTreeSHA'], 'dfb1 exact recipe Git tree differs')
            commit = legacy._json(legacy._file(root, recipe['commitReceipt'], read=True))
            directory = legacy._json(legacy._file(root, recipe['directoryReceipt'], read=True))
            _require(same_identity((commit['id'], commit['project_id'], commit['parent_ids'], commit['web_url']),
                                  (package['c'], 1, recipe['parents'], 'https://gitlab.alpinelinux.org/alpine/aports/-/commit/' + package['c'])),
                     'dfb1 official commit receipt differs')
            expected_entries = [{'id': row['gitBlob'], 'name': row['path'].rsplit('/', 1)[-1], 'type': 'blob',
                                 'path': row['path'].removeprefix('aports/' + package['c'] + '/'), 'mode': row['gitMode']}
                                for row in files]
            _require(same_identity(directory, expected_entries), 'dfb1 full exact-commit directory receipt differs')
            builds = [raw for row, raw in measured if row['path'] == prefix + '/APKBUILD']
            _require(len(builds) == 1, 'dfb1 exact APKBUILD absent')
            body = builds[0].decode('utf-8')
            version, release = package['V'].rsplit('-r', 1)
            _require(re.search(r'^pkgname=' + re.escape(package['o']) + r'$', body, re.M)
                     and re.search(r'^pkgver=' + re.escape(version) + r'$', body, re.M)
                     and re.search(r'^pkgrel=' + re.escape(release) + r'$', body, re.M), 'dfb1 APKBUILD package identity differs')
            sums = re.findall(r'^([a-f0-9]{128})  (.+)$', body, re.M)
            _require(sums and len({name for _, name in sums}) == len(sums), 'dfb1 APKBUILD checksum scope differs')
            # Exact source ownership and acquisition/notice bytes are checked
            # below; no checksum or arbitrary source JSON grants admission.
            self._recipe_inputs(root, publisher_root, selector, recipe, measured, sums)

    def _recipe_inputs(self, root, publisher_root, selector, recipe, measured, sums):
        acquisition = legacy._json(legacy._file(root, selector['sourceAcquisition'], read=True))
        notices = legacy._json(legacy._file(root, selector['noticeInventory'], read=True))
        for document, schema, count in (
                (acquisition, 'polaris-exact-oci-delta-source-acquisition-v1', 'newDownloads'),
                (notices, 'polaris-exact-oci-delta-notice-inventory-v1', 'newNotices')):
            _require(same_identity((document['schema'], document['sourceCommit'], document['producerRunId'],
                                   document['producerAttempt'], document[count]), (schema, SOURCE, RUN_ID, ATTEMPT, 2))
                     and document['legalConclusion'] is False, 'dfb1 source/notice origin/count differs')
        _require(acquisition['historicalReceiptsUnmodified'] is True
                 and same_identity(acquisition['sharedExternalInputs'], ['nftables-1.1.7.tar.xz', 'posixtz-0.5.tar.xz']),
                 'dfb1 historical acquisition ownership differs')
        _require(same_identity([r['path'] for r in acquisition['references']], [
                    previous.DIRECTORY + '/source-acquisition.json', 'release/dependency-sources/oci/source-acquisition.json'])
                 and same_identity([r['path'] for r in notices['references']], [previous.DIRECTORY + '/notice-inventory.json']),
                 'dfb1 source/notice predecessor links differ')
        for row in acquisition['references'] + notices['references']:
            legacy._file(publisher_root, row)
        sources = acquisition['newSources']
        _require(type(sources) is list and [s['name'] for s in sources] == list(_NEW_SOURCES), 'dfb1 exact IANA source scope differs')
        source_by_name = {s['name']: s for s in sources}
        external = recipe['externalInputs']
        _require(type(external) is list and len({s['name'] for s in external}) == len(external)
                 and [s['name'] for s in external] == (['nftables-1.1.7.tar.xz'] if recipe['origin'] == 'nftables'
                     else ['tzcode2026f.tar.gz', 'tzdata2026f.tar.gz', 'posixtz-0.5.tar.xz']), 'dfb1 exact external input scope differs')
        local = {row['path'].rsplit('/', 1)[-1]: raw for row, raw in measured}
        inputs = {row['name']: row for row in external}
        _require(all(name in local or name in inputs for _, name in sums)
                 and all(name in {n for _, n in sums} for name in inputs), 'dfb1 APKBUILD checksum input closure differs')
        for checksum, name in sums:
            if name in local:
                _require(legacy._sha(local[name], 'sha512') == checksum, 'dfb1 local recipe checksum differs')
            else:
                _require(same_identity(inputs[name]['sha512'], checksum), 'dfb1 external recipe checksum differs')
        for item in external:
            name = item['name']
            if name in _NEW_SOURCES:
                source = source_by_name[name]
                _require(same_identity(tuple(item[k] for k in ('name', 'bytes', 'sha256', 'sha512', 'requestedURL', 'sourceArchivePath')),
                                      tuple(source[k] for k in ('name', 'bytes', 'sha256', 'sha512', 'requestedURL', 'path')))
                         and item['ownership'] == 'new-source-acquisition', 'dfb1 new source association differs')
            else:
                owner = item['historicalOwner']
                _require(item['notReacquired'] is True and item['sourceArchiveRetainedHere'] is False
                         and item['ownership'] == 'historical-source-acquisition-unmodified-reuse', 'dfb1 historical source relabelled')
                old = legacy._json(legacy._file(publisher_root, owner['sourceAcquisition'], read=True))
                legacy._file(publisher_root, owner['materialMap'])
                exact = [s for s in old if s['name'] == name]
                _require(len(exact) == 1 and same_identity(exact[0], item['historicalAcquisitionRecord'])
                         and exact[0]['verified'] is True
                         and same_identity(tuple(item[k] for k in ('name', 'bytes', 'sha256', 'sha512', 'historicalAcquisitionURL')),
                                           tuple(exact[0][k] for k in ('name', 'bytes', 'sha256', 'sha512', 'url'))),
                         'dfb1 historical external source bytes/owner differ')
        notice_files = notices['files']
        _require(type(notice_files) is list and len(notice_files) == 2
                 and [f['sourceArchivePath'] for f in notice_files] == ['sources/' + name for name in _NEW_SOURCES],
                 'dfb1 notice source scope differs')
        for source, notice in zip(sources, notice_files):
            name = source['name']; identity = _NEW_SOURCES[name]
            data = legacy._file(root, source, read=True)
            _require(same_identity((len(data), legacy._sha(data), legacy._sha(data, 'sha512')), identity)
                     and same_identity(tuple(source[k] for k in ('bytes', 'sha256', 'sha512')), identity)
                     and source['path'] == 'sources/' + name
                     and source['requestedURL'] == 'https://www.iana.org/time-zones/repository/releases/' + name,
                     'dfb1 exact IANA source bytes/URL differ')
            request = legacy._json(legacy._file(root, source['getRequest'], read=True))
            receipt = legacy._json(legacy._file(root, source['getReceipt'], read=True))
            final = 'https://data.iana.org/time-zones/releases/' + name
            _require(request['method'] == receipt['method'] == 'GET'
                     and request['url'] == receipt['url'] == receipt['requestedURL'] == source['requestedURL']
                     and request['retry'] is False and request['noAuthentication'] is receipt['noAuthentication'] is True
                     and request['expectedSHA512'] == identity[2]
                     and request['SHA512ExpectationSource'] == 'aports/' + _DELTA_PACKAGES[1]['c'] + '/main/tzdata/APKBUILD'
                     and same_identity((request['timeoutSeconds'], request['maxBytes']), (30, 8 * 1024**2))
                     and same_identity((receipt['HTTP'], receipt['bytes'], receipt['sha256'], receipt['sha512']), (200, *identity))
                     and receipt['status'] == 'VERIFIED' and receipt['fullGet'] is True
                     and receipt['recipeSHA512Verified'] is True and receipt['openResponseAndBodyClosed'] is True
                     and receipt['effectiveURL'] == final and receipt['path'] == source['path']
                     and not any(k in receipt for k in ('errorType', 'error', 'readError')), 'dfb1 actual IANA GET receipt differs')
            redirects = receipt['redirects']
            _require(type(redirects) is list and len(redirects) == 1
                     and same_identity(redirects[0]['HTTP'], 302) and redirects[0]['from'] == source['requestedURL']
                     and redirects[0]['to'] == final and receipt['headers'] == receipt['responseHeaders']
                     and receipt['responseHeaders']['Content-Length'] == str(identity[0]), 'dfb1 IANA redirect/response differs')
            for headers in [receipt['headers'], receipt['responseHeaders'], redirects[0]['headers']]:
                _require(type(headers) is dict and all(k.lower() in {'date', 'content-type', 'content-length', 'last-modified', 'etag'} for k in headers),
                         'dfb1 unsafe retained source response header')
            _require(notice['path'] == 'notices/' + name + '/LICENSE' and notice['archiveMember'] == 'LICENSE'
                     and notice['sourceArchiveSHA256'] == identity[1], 'dfb1 notice ownership differs')
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
                members, names, expanded = [], set(), 0
                for member in archive:
                    name = member.name.rstrip('/')
                    expanded += member.size
                    _require(name not in names and len(names) < 4096 and expanded <= 128 * 1024**2,
                             'dfb1 source tar resource/member closure differs')
                    names.add(name); members.append(member)
                    legacy._relative(member.name.rstrip('/'))
                    _require((member.isfile() or member.isdir()) and 0 <= member.size <= 16 * 1024**2, 'dfb1 unsafe source tar member')
                found = [m for m in members if m.name == 'LICENSE']
                _require(len(found) == 1 and found[0].isfile() and same_identity(found[0].size, notice['bytes'])
                         and archive.extractfile(found[0]).read() == legacy._file(root, notice, read=True), 'dfb1 source archive notice bytes differ')
        shared_notices = notices['sharedNotices']
        _require(type(shared_notices) is list and len(shared_notices) == 1, 'dfb1 exact shared nftables notice required')
        notice = shared_notices[0]
        _require(same_identity(tuple(notice[k] for k in ('path', 'bytes', 'sha256', 'archiveMember', 'sourceArchiveName', 'sourceArchiveSHA256')),
                              ('release/licenses/oci/notices/nftables-1.1.7.tar.xz/nftables-1.1.7/COPYING', 18341,
                               '4ee1e51baf5f3166712fa0c3e01338c7257e50ddef245d28bb14ad68f6070ba5',
                               'nftables-1.1.7/COPYING', 'nftables-1.1.7.tar.xz', 'a6fbf060d8d4fff001517a2b94f356bb4366bfbf0ba366366f9d27cc38caa58f'))
                 and notice['ownership'] == 'historical-unmodified-reuse' and notice['reextractedNow'] is False,
                 'dfb1 shared notice ownership/source differs')
        legacy._file(publisher_root, notice)
        legacy._file(publisher_root, notice['historicalMaterialMap'])


_selection = _MaterialDelta(
    source=SOURCE, tree=TREE, tag=TAG, tag_object=TAG_OBJECT, run_id=RUN_ID, attempt=ATTEMPT,
    directory=DIRECTORY, selector_bytes=SELECTOR_BYTES, selector_sha256=SELECTOR_SHA256,
    schema=SCHEMA, previous=previous, bundle_members=118,
)
_selector_record = _selection._selector_record
_historical_sources = _selection._historical_sources
_reassociation = _selection._reassociation
_load = _selection._load
load_for_run = _selection.load_for_run
bundle_name = _selection.bundle_name
check_image = _selection.check_image
write_bundle = _selection.write_bundle
record = _selection.record
