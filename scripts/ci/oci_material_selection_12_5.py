"""Exact 332935 OCI source reassociation; old source bytes are never new binaries."""
from oci_material_reassociation import OCIReassociation

import oci_material_selection_12_3 as previous

SOURCE = '332935c310e78e15319d434f33a9103329200931'
TREE = '6a8371b425370326528658e9b0cace926cf76b2d'
TAG = 'v1.15.0-polaris-alpha.12.5'
TAG_OBJECT = '76e4f7db6767472952d09e4cf35b2cf90c223fbf'
RUN_ID = 40320104873
ATTEMPT = 1
DIRECTORY = 'release/dependency-sources/oci/selections/40320104873-attempt1'
SELECTOR_BYTES = 10502
SELECTOR_SHA256 = 'b93cd6b8337e404829cdf804b09c74ff5ae6805b89bc733a2aae1c95cd3d11a4'
SCHEMA = 'polaris-exact-oci-source-reassociation-12.5-policy-v1'


_selection = OCIReassociation(
    source=SOURCE, tree=TREE, tag=TAG, tag_object=TAG_OBJECT, run_id=RUN_ID, attempt=ATTEMPT,
    directory=DIRECTORY, selector_bytes=SELECTOR_BYTES, selector_sha256=SELECTOR_SHA256, schema=SCHEMA,
    previous=previous, bundle_members=83,
)
_selector_record = _selection._selector_record
_historical_sources = _selection._historical_sources
_reassociation = _selection._reassociation
_load = _selection._load
load_for_run = _selection.load_for_run
_checked = _selection._checked
bundle_name = _selection.bundle_name
check_image = _selection.check_image
write_bundle = _selection.write_bundle
record = _selection.record
