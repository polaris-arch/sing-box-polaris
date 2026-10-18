# Reviewable publication preparation

This branch only prepares ten assets offline. It does not build Cronet or the
six CLI binaries, change tags, upload releases, or delete old releases.

1. Run scripts/polaris_native_distribution.py with --archive-dir pointing to
   the six exact original accepted archives, --source-asset pointing to the
   exact v4 archive, and --output an absent destination. Inputs are fixed by
   inputs.json SHA372549826169567a168d313f28253d2b4a500d925d651390925189a93f84a043.
   All old binary/provenance/mode/signature bytes are preserved. Whole268 notice
   records, controlled index, acquisition/build instructions and coverage
   decisions enter every native archive. Every new member and outer archive is
   read back against its initially fixed expected bytes. Failure leaves no
   final destination. No public availability is asserted by this command.
2. Parent independently reviews the source/material finite applicability,
   actual package members/hashes and publisher code. prepared-upload-assets.json
   is the exact ten-asset list; manifest SHA
   ac47e16d7c823acb770b0959f703ef441656a1115f7632b85299e542887cec15.
   prepared-release-receipt.json separates original producer/run, material,
   binary identity/signatures and new packaging. The exact v4 remains unchanged.
3. Only after review and explicit publication authorization, run
   scripts/polaris_publish_distribution.py stage-draft with --approved-head
   set to the reviewed exact publication commit, --manifest the actual local
   UPLOAD-ASSETS.json, --manifest-sha256 the above reviewed value, and --receipt
   an external evidence path. It creates an annotated proposed tag targeting
   exacta01, pushes only that tag to the verified polaris fork remote, creates
   a draft prerelease and uploads the ten private verified snapshots without
   clobber. Exact remote asset names/sizes/digests and tag peel must match.
   It refuses an existing proposed tag; partial failures require inspection,
   never force overwrite or rollback deletion.
   Draft lookup uses the authenticated paginated release list and requires
   exactly one matching tag; the REST by-tag endpoint only returns published
   releases. If stage fails after creating an empty draft, preserve its failure
   receipt and inspect the remote tag object, peeled source, release ID, notes
   and empty asset set. After independent review of this recovery change, use
   resume-empty-draft with the new reviewed --approved-head, exact --release-id
   and --expected-tag-object, unchanged manifest/hash and a new receipt path.
   It does not create tags/releases and rejects nonempty drafts, duplicate tag
   releases, modified notes or identity drift. No automatic retry or clobber.
4. With the exact returned --release-id and the same reviewed source/manifest,
   the explicit publish action changes only draft/prerelease/latest flags,
   then anonymously downloads all ten stable release URLs and verifies each
   size/SHA256. Completion is public-downloads-verified, not merely upload/API
   success. A failed readback is an incomplete publication with preserved
   release evidence; verify-public allows a later read-only retry. There is
   no cleanup action. Follow old-release-cleanup-dependencies.json separately.

No signing is performed: Windows cores have no certificate table, macOS amd64
is unsigned, macOS arm64 linker ad-hoc bytes remain unchanged. No notarization,
signature trust, device network or mobile carrier validation is claimed.
The source/notice coverage decision's remaining finite runtime applicability
and final independent review remain open; blanket compiler/SDK byte archives
and Android/Apple carriers are not desktop publication prerequisites.
