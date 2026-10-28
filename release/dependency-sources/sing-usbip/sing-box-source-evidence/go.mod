// Read-only, partial source evidence, not a buildable sing-box checkout.
// This boundary keeps root ./... tools on live sources. Original files remain
// byte-bound by ../source-tar-materials-manifest.json and checked by
// scripts/ci/patch_test_packages.py; do not add dependencies or replacements.
module github.com/polaris-arch/sing-box-polaris/source-evidence/sing-usbip

go 1.27.0
