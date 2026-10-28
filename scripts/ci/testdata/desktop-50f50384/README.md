# Pinned desktop source fixtures

Exact, unmodified `scripts/package.ts` and `scripts/afterPack.cjs` from
SagerNet/sing-box-for-desktop commit `50f503849148dd73fa4f4bc231119acf5b2f3d7a`.
The adjacent LICENSE is that source revision's original notice. These files
are source inputs for overlay regression controls, never executable test helpers.
The test verifies their Git blob and SHA256 against the production client manifest
before applying the complete declared transforms. This retains unchanged signed
checks in the actual baseline, which are absent from an edits-only concatenation.

Upstream: https://github.com/SagerNet/sing-box-for-desktop/tree/50f503849148dd73fa4f4bc231119acf5b2f3d7a/scripts
