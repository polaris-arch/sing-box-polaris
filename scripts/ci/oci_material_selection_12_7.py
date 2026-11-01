"""Exact 3155 OCI source reassociation; old source bytes are never new binaries."""
from oci_material_reassociation import OCIReassociation

import oci_material_selection_12_6 as previous

SOURCE = '3155c9151f553967aabcee93f09e51084fc89899'
TREE = '457a8906cd3088578aa7e9d93185f07142178b5b'
TAG = 'v1.15.0-polaris-alpha.12.7'
TAG_OBJECT = '3f6ca510d99cd871e465b82b16e9ab069ec539d8'
RUN_ID = 40952253134
ATTEMPT = 1
DIRECTORY = 'release/dependency-sources/oci/selections/40952253134-attempt1'
SELECTOR_BYTES = 10498
SELECTOR_SHA256 = 'fbaef5f2158e984aacaf710ee284b2d0b2c910a977ef7bcb4eba00390b93fbc3'
SCHEMA = 'polaris-exact-oci-source-reassociation-12.7-policy-v1'


_selection = OCIReassociation(
    source=SOURCE, tree=TREE, tag=TAG, tag_object=TAG_OBJECT, run_id=RUN_ID, attempt=ATTEMPT,
    directory=DIRECTORY, selector_bytes=SELECTOR_BYTES, selector_sha256=SELECTOR_SHA256, schema=SCHEMA,
    previous=previous, bundle_members=98, reference_version=2,
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
