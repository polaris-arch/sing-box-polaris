# Locked builder configuration regression

scheme.json is the unmodified app-builder-lib 26.15.3 npm package schema, verified against the exact SHA512 in the fixed desktop client's pnpm-lock.yaml. provenance.json records acquisition and hashes. The project's original MIT license is retained as LICENSE with its separately identified official repository snapshot; it does not change the schema's npm identity.

electron-builder.yml is the fixed original client configuration, Git blob 295ccd9cfe7b000796944b770b9e1f3704535710. Its original client author and license remain in the adjacent desktop fixture LICENSE and the delivered client sources. Tests apply the actual source-owned overlay and validate the complete configuration, including Windows builds' shared Linux settings. No package lock or upstream source is modified.

The original npm schemaValidator.js was additionally exercised with the lock-pinned Ajv 8.20.0 and dependencies, all tarball SHA512s verified, without running installation scripts. The offline Source regression uses Draft7Validator against the same complete schema and includes the original invalid nesting as a negative control; it does not claim to replace all electron-builder runtime checks.
