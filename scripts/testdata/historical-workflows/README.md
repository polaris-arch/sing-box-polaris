# Historical workflow fixtures

These are byte-for-byte snapshots from commit
`02e73561d6bab147d507cfe6bf7c90051ffdb9ff`, retained for the existing
tests of frozen producer scripts. They are outside `.github/workflows/`
and must not be dispatched as current Actions workflows.

The native and DNS candidates pin the retired `a01da7a` and `aafc521`
source batches. The production pair is restricted to the old
`polaris-arch/polaris-box` repository. Current source checks, platform
matrices, candidate builds, and guarded publication remain in the active
workflows; historical runs, logs, artifacts, and source recipes remain intact.

| Fixture | SHA-256 |
| --- | --- |
| `polaris-native-candidate.yml` | `57d67de52d5b08566c57309073c3c65fc2d3de3c1aeb7934d9a1a3f3d665e183` |
| `polaris-dns-native-candidate.yml` | `a43b4bb1be2acaf1df970e5701e729819fc204ba77f819e2f7fb6f750e965080` |
| `polaris-production-native.yml` | `84bd0147cd5e569f812693e37adeaf6fa589fff96e6a78f3a0d3eb7a7c6ed160` |
| `polaris-production-release.yml` | `024425aded5dedcb28452a54f72092731ca8e528408c75a37dfddd22112fef7b` |
