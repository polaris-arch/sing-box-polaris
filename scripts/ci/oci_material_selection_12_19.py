"""Exact S19 OCI materials: 214 shared and 29 measured package associations."""
import gzip
import io
import re
import tarfile

from release_identity import same_identity
import oci_material_supplement as legacy
import oci_material_selection_12_9 as previous
from oci_material_reassociation import OCIReassociation, _image_identity

SOURCE = 'd8727ed53de26cfd13c95f96d0a69235792d221b'
TREE = 'ef6623adf82eb67541221ee46909e52157da396a'
TAG = 'v1.15.0-polaris-alpha.12.19'
TAG_OBJECT = '47a4c6fa457c12cc7e871b61c8beaf1620ba210a'
RUN_ID = 42315358374
ATTEMPT = 1
DIRECTORY = 'release/dependency-sources/oci/selections/42315358374-attempt1'
SELECTOR_BYTES = 12742
SELECTOR_SHA256 = 'b65b0a6d9baabb444dbf34aaa995f2b74fab59964c8f4f35f58b02022535d469'
SCHEMA = 'polaris-exact-oci-material-delta-12.19-policy-v1'
_require = legacy._require
_PACKAGE_PINS = {
    'oci-linux-386': '476eb3e1a1111550346e41a5e5e8f564898b31ac3e0b4312ed9b5d10588703c9',
    'oci-linux-amd64': '0b316792598c6735e8e042b045c2bfec1fc4dc5bbbff4fafa2e05250649ef8cb',
    'oci-linux-arm-v6': '8784d7114f9469f7a1e25eb140a51f7368812adba8b90eba438c990830db50d4',
    'oci-linux-arm-v7': '6bcfaeedd93a021edbb7a86325a30ad054f6f97b7af430a4da3559ac04a5786c',
    'oci-linux-arm64': 'f043acb2804ee1d210d07a623d0e3e5113b930be6c1f40bf2333b66ca0fe4133',
    'oci-linux-loong64': '0ebda1a5f46bdba8e1d5ed5a72d79a3a877aae0f7faca24961a9f5d07c714ef1',
    'oci-linux-ppc64le': '75665508c19186ee7ec84405d23d1d73c7198eba823e174e8c61ecaac4b15da0',
    'oci-linux-riscv64': 'b28780e33ad281dfbfc0a00d2eb8172776a3b963bdcea1c01b91c9f33a31b797',
    'oci-linux-s390x': '33f97b9604572049c7f4580f7daf470c2903beab9642443cc2f8372dee842ba3',
}
_ALPINE_BASE = '3f4d6b32e26703c6082839234f43769d5046b3ac7c910033911d1e71d8cd630a'
_RECIPES = {
    'alpine-base': ('105b835acd9971b9770fb61f5a1ddcc133c180dc', 'a3af2bd7d397d1907757514932ee7896f4fe63cd', '3.24.4', 1),
    'apk-tools': ('13685e8f2cf1c103cbba2fb9efcfcf19f4918df0', '673ba2e9b8e6af2836712927054e750015130b4f', '3.0.9', 2),
    'tzdata': ('63faba7f731ad47f4cd60d3ff34ff1aadd49c091', '8152e72979a93582fa93b8a43fd0ad6dc5e6f230', '2026f', 3),
}


class _MaterialDelta(OCIReassociation):
    def _selection_schema(self):
        return 'polaris-exact-oci-material-delta-selection-v1'

    def _association_counts(self):
        return {'sharedPackageAssociationCount': 214, 'newPackageAssociationCount': 29,
                'crossArchitectureSourceAssociationCount': 0, 'newRecipeCount': 3,
                'changedBaseDependencyCount': 8}

    def _reassociation(self, root, selector, reference, material_map, historical, _old_root, _old_map):
        _require(type(reference) is dict and set(reference) == {
            'schema', 'sourceCommit', 'producerRunId', 'producerAttempt', 'legalConclusion',
            'materialMapSHA256', 'artifacts'}, 'S19 reference fields differ')
        _require(type(material_map) is dict and set(material_map) == {
            'schema', 'sourceCommit', 'producerRunId', 'producerAttempt', 'legalConclusion', 'sharedMaterials',
            'packageAssociationCount', 'newRecipeCount', 'exactPackageAssociations', 'newPackageAssociations',
            'crossArchitectureSourceAssociations', 'baseDependencyChanges', 'newRecipes'}, 'S19 material map fields differ')
        _require(reference['schema'] == 'polaris-current-oci-material-reference-v1'
                 and material_map['schema'] == 'polaris-exact-oci-material-delta-v1'
                 and same_identity(reference['materialMapSHA256'], selector['materialMap']['sha256']),
                 'S19 reference/map identity differs')
        for document in (reference, material_map):
            _require(same_identity((document['sourceCommit'], document['producerRunId'], document['producerAttempt']),
                                  (SOURCE, RUN_ID, ATTEMPT)) and document['legalConclusion'] is False,
                     'S19 material source/run/attempt identity differs')
        _require(same_identity(material_map['sharedMaterials'], selector['sharedMaterials'])
                 and same_identity(material_map['packageAssociationCount'], 243)
                 and same_identity(material_map['newRecipeCount'], 3)
                 and same_identity(material_map['crossArchitectureSourceAssociations'], []), 'S19 association ownership/count differs')
        _require(type(reference['artifacts']) is dict and set(reference['artifacts']) == legacy.ARTIFACT_NAMES,
                 'S19 requires exact nine OCI profiles')
        shared, changed, bases = [], [], []
        for name, row in sorted(reference['artifacts'].items()):
            old = historical['artifacts'][name]
            _require(type(row) is dict and set(row) == previous._IMAGE_FIELDS | {'baseDependencies', 'repositories', 'packages'},
                     'S19 complete profile fields differ')
            image = {key: row[key] for key in previous._IMAGE_FIELDS}; _image_identity(image)
            _require(same_identity(image, selector['artifacts'][name])
                     and same_identity(row['platform'], old['platform'])
                     and same_identity(row['repositories'], old['repositories']), 'S19 image/platform/repository differs')
            expected_base = old['baseDependencies'] if name == 'oci-linux-loong64' else [
                {'uri': old['baseDependencies'][0]['uri'], 'digest': {'sha256': _ALPINE_BASE}}]
            _require(same_identity(row['baseDependencies'], expected_base), 'S19 exact base dependency differs')
            if not same_identity(row['baseDependencies'], old['baseDependencies']):
                bases.append({'artifact': name, 'previous': old['baseDependencies'], 'actual': row['baseDependencies']})
            packages = row['packages']
            _require(type(packages) is list and len(packages) == 27, 'S19 package scope differs')
            for package in packages:
                legacy._package(package)
            _require(len({p['P'] for p in packages}) == 27
                     and same_identity(packages, sorted(packages, key=lambda p: (p['P'], p['V'], p['A'])))
                     and legacy._sha(legacy._canonical(packages)) == _PACKAGE_PINS[name],
                     'S19 exact measured seven-field package set differs')
            for package in packages:
                association = {'artifact': name, 'package': package}
                (shared if any(same_identity(package, p) for p in old['packages']) else changed).append(association)
        _require(len(shared) == 214 and len(changed) == 29 and len(bases) == 8
                 and same_identity(material_map['exactPackageAssociations'], shared)
                 and same_identity(material_map['newPackageAssociations'], changed)
                 and same_identity(material_map['baseDependencyChanges'], bases), 'S19 exact 214+29/base association closure differs')
        _require({(r['package']['o'], r['package']['c']) for r in changed}
                 == {(origin, row[0]) for origin, row in _RECIPES.items()}, 'S19 changed recipe ownership differs')
        self._delta_materials(root, selector, material_map)
        return reference

    def _delta_materials(self, root, selector, material_map):
        publisher_root = root
        for _ in legacy._relative(DIRECTORY).parts:
            publisher_root = publisher_root.parent
        _require(legacy._path(publisher_root, DIRECTORY) == root, 'S19 material root differs')
        recipes = material_map['newRecipes']
        _require(type(recipes) is list and [r['origin'] for r in recipes] == list(_RECIPES),
                 'S19 exact three recipe closures required')
        for recipe in recipes:
            origin = recipe['origin']; commit, tree, version, count = _RECIPES[origin]
            _require(same_identity((recipe['repository'], recipe['repositoryHost'], recipe['projectId'],
                                   recipe['commit'], recipe['directoryTreeSHA']),
                                  ('alpine/aports', 'gitlab.alpinelinux.org', 1, commit, tree)),
                     'S19 official recipe origin/commit differs')
            project = legacy._json(legacy._file(root, recipe['projectReceipt'], read=True))
            _require(same_identity((project['id'], project['path_with_namespace'], project['web_url']),
                                  (1, 'alpine/aports', 'https://gitlab.alpinelinux.org/alpine/aports')),
                     'S19 official project identity differs')
            files = recipe['files']
            _require(type(files) is list and len(files) == count, 'S19 full recipe directory scope differs')
            prefix = 'aports/' + commit + '/main/' + origin
            measured = []
            for row in files:
                raw = (legacy._file(publisher_root, row['historicalFile'], read=True) if 'historicalFile' in row
                       else legacy._file(root, row, read=True))
                _require(same_identity((len(raw), legacy._sha(raw)), (row['bytes'], row['sha256'])),
                         'S19 recipe member byte identity differs')
                measured.append((row, raw))
            _require(previous._git_directory(measured, prefix) == tree, 'S19 exact recipe Git tree differs')
            receipt = legacy._json(legacy._file(root, recipe['commitReceipt'], read=True))
            directory = legacy._json(legacy._file(root, recipe['directoryReceipt'], read=True))
            _require(same_identity((receipt['id'], receipt['project_id'], receipt['parent_ids'], receipt['web_url']),
                                  (commit, 1, recipe['parents'], 'https://gitlab.alpinelinux.org/alpine/aports/-/commit/' + commit)),
                     'S19 official commit receipt differs')
            expected_entries = [{'id': r['gitBlob'], 'name': r['path'].rsplit('/', 1)[-1], 'type': 'blob',
                                 'path': r['path'].removeprefix('aports/' + commit + '/'), 'mode': r['gitMode']} for r in files]
            _require(same_identity(directory, expected_entries), 'S19 complete exact-commit directory receipt differs')
            builds = [raw for row, raw in measured if row['path'] == prefix + '/APKBUILD']
            _require(len(builds) == 1, 'S19 exact APKBUILD absent')
            body = builds[0].decode('utf-8')
            _require(re.search(r'^pkgname=' + re.escape(origin) + r'$', body, re.M)
                     and re.search(r'^pkgver=' + re.escape(version) + r'$', body, re.M)
                     and re.search(r'^pkgrel=0$', body, re.M), 'S19 APKBUILD package identity differs')
            sums = re.findall(r'^([a-f0-9]{128})  (.+)$', body, re.M)
            _require(len({name for _, name in sums}) == len(sums), 'S19 APKBUILD duplicate checksum')
            self._recipe_inputs(root, publisher_root, selector, recipe, measured, sums)

    def _recipe_inputs(self, root, publisher_root, selector, recipe, measured, sums):
        acquisition = legacy._json(legacy._file(root, selector['sourceAcquisition'], read=True))
        notices = legacy._json(legacy._file(root, selector['noticeInventory'], read=True))
        for document, schema, count in (
                (acquisition, 'polaris-exact-oci-12.19-source-acquisition-v1', 'newDownloads'),
                (notices, 'polaris-exact-oci-12.19-notice-inventory-v1', 'newNotices')):
            _require(same_identity((document['schema'], document['sourceCommit'], document['producerRunId'],
                                   document['producerAttempt'], document[count]), (schema, SOURCE, RUN_ID, ATTEMPT, 1))
                     and document['legalConclusion'] is False, 'S19 source/notice origin/count differs')
        _require(acquisition['historicalReceiptsUnmodified'] is True
                 and notices['historicalNoticesUnmodified'] is True
                 and same_identity(notices['recipeSourceOnlyOrigins'], ['alpine-base'])
                 and same_identity([r['path'] for r in acquisition['references']], [
                     previous.DIRECTORY + '/source-acquisition.json', 'release/dependency-sources/oci/source-acquisition.json'])
                 and same_identity([r['path'] for r in notices['references']], [previous.DIRECTORY + '/notice-inventory.json']),
                 'S19 historical source/notice ownership differs')
        for row in acquisition['references'] + notices['references']:
            legacy._file(publisher_root, row)
        sources, reused = acquisition['newSources'], acquisition['reusedSources']
        names = ['tzcode2026f.tar.gz', 'tzdata2026f.tar.gz', 'posixtz-0.5.tar.xz']
        _require(type(sources) is list and len(sources) == 1 and sources[0]['name'] == 'apk-tools-v3.0.9.tar.gz'
                 and type(reused) is list and [r['name'] for r in reused] == names, 'S19 exact external source scope differs')
        for index, item in enumerate(reused):
            owner = acquisition['references'][0 if index < 2 else 1]
            _require(same_identity(item['historicalOwner'], owner) and item['notReacquired'] is True
                     and item['sourceArchiveRetainedHere'] is False, 'S19 historical source ownership differs')
            historical = legacy._json(legacy._file(publisher_root, owner, read=True))
            rows = historical['newSources'] if index < 2 else historical
            exact = [row for row in rows if row['name'] == item['name']]
            _require(len(exact) == 1 and same_identity(item['historicalRecord'], exact[0])
                     and (index < 2 or exact[0]['verified'] is True), 'S19 historical acquisition record differs')
        expected_inputs = {
            'alpine-base': [],
            'apk-tools': [dict(name=sources[0]['name'], sha512=sources[0]['sha512'],
                               ownership='new-source-acquisition', acquisitionIndex=0)],
            'tzdata': [dict(name=item['name'], sha512=item['historicalRecord']['sha512'],
                            ownership='historical-source-acquisition-unmodified-reuse', acquisitionIndex=index)
                       for index, item in enumerate(reused)],
        }
        external = recipe['externalInputs']
        _require(same_identity(external, expected_inputs[recipe['origin']]), 'S19 external recipe association differs')
        local = {row['path'].rsplit('/', 1)[-1]: raw for row, raw in measured}
        checksums = {name: checksum for checksum, name in sums}
        _require(set(checksums) == (set(local) - {'APKBUILD'}) | {row['name'] for row in external},
                 'S19 APKBUILD checksum input closure differs')
        for name, raw in local.items():
            if name != 'APKBUILD':
                _require(legacy._sha(raw, 'sha512') == checksums[name], 'S19 local recipe checksum differs')
        for item in external:
            _require(same_identity(item['sha512'], checksums[item['name']]), 'S19 external recipe checksum differs')
        if recipe['origin'] != 'apk-tools':
            return
        source = sources[0]
        identity = (392363, '0063029a3eb228fd494b6804613ac53c30372a1a79ac83e23cefa78368767726',
                    '933f9a3645e225a8e433951e57fce979d68a933b5cc066591f5da35c561c07ea476c0ada184fa81ab8eea1431f9b475735ad68c598072e26c0a74debf65a680f')
        url = 'https://gitlab.alpinelinux.org/alpine/apk-tools/-/archive/v3.0.9/apk-tools-v3.0.9.tar.gz'
        data = legacy._file(root, source, read=True)
        _require(same_identity((len(data), legacy._sha(data), legacy._sha(data, 'sha512')), identity)
                 and same_identity(tuple(source[k] for k in ('bytes', 'sha256', 'sha512')), identity)
                 and source['requestedURL'] == url and source['path'] == 'sources/apk-tools-v3.0.9.tar.gz',
                 'S19 exact upstream archive bytes/URL differ')
        receipt = legacy._json(legacy._file(root, source['getReceipt'], read=True))
        _require(same_identity((receipt['HTTP'], receipt['actualBodyBytes'], receipt['actualBodySHA256'], receipt['actualBodySHA512']),
                              (200, *identity)) and receipt['actualEOF'] is True and receipt['fullGzipCRCAndEOF'] is True
                 and receipt['effectiveURL'] == receipt['request']['url'] == url
                 and receipt['request']['method'] == 'GET' and receipt['request']['authSent'] is False
                 and receipt['request']['redirectFollowed'] is False and receipt['materialsAccepted'] is False
                 and receipt['sourceOrRecipeExecuted'] is False
                 and same_identity((receipt['fullExpandedBytes'], receipt['tarMemberCount']), (1761280, 453))
                 and receipt['responseHeaders'].get('Content-Length') == str(identity[0])
                 and all(k.lower() in {'date', 'content-type', 'content-length', 'last-modified', 'etag'}
                         for k in receipt['responseHeaders']), 'S19 actual upstream GET receipt differs')
        files = notices['files']
        _require(type(files) is list and len(files) == 1 and same_identity(files[0], {
            'path': 'notices/apk-tools-v3.0.9/LICENSE', 'bytes': 17622,
            'sha256': 'b3c87315aae4c9f276c37168f2655dd8bd990544d7a0bbfb929664155c7ab257',
            'archiveMember': 'apk-tools-v3.0.9/LICENSE', 'sourceArchivePath': source['path'],
            'sourceArchiveSHA256': identity[1]}), 'S19 exact notice ownership differs')
        # Hash-pinned archive, full gzip CRC/EOF and bounded tar metadata only;
        # the one measured source symlink is never extracted or executed.
        expanded = gzip.decompress(data)
        _require(len(expanded) == 1761280, 'S19 upstream expanded size differs')
        with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
            names, notice = set(), None
            for member in archive:
                name = member.name.rstrip('/')
                legacy._relative(name)
                _require(name not in names and len(names) < 453 and 0 <= member.size <= 16 * 1024**2
                         and (member.isfile() or member.isdir() or (member.issym()
                              and name == 'apk-tools-v3.0.9/src/apk-static.c' and member.linkname == 'apk.c')),
                         'S19 unsafe/duplicate upstream tar member')
                names.add(name)
                if name == files[0]['archiveMember']:
                    _require(member.isfile(), 'S19 upstream notice is not a file')
                    notice = archive.extractfile(member).read()
            _require(len(names) == 453 and notice == legacy._file(root, files[0], read=True),
                     'S19 upstream archive notice bytes differ')


_selection = _MaterialDelta(
    source=SOURCE, tree=TREE, tag=TAG, tag_object=TAG_OBJECT, run_id=RUN_ID, attempt=ATTEMPT,
    directory=DIRECTORY, selector_bytes=SELECTOR_BYTES, selector_sha256=SELECTOR_SHA256,
    schema=SCHEMA, previous=previous, bundle_members=136,
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
