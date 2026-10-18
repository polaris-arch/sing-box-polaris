# Pinned client packaging source fixture

Exact unmodified `Jailbreak/package.sh` from SagerNet/sing-box-for-apple commit `e232aaf22d6d68773196ffc8e6e79684a6be717c`.
Git blob `417a29d02dcff29b8a156aee161fd6e53bc749c0`; SHA256 `0aac83ea17ee10855411522f79947a17b1e48a3b7e59f0cb62b27ef2acd2b1aa`.
The adjacent LICENSE is the original notice from that revision.

The regression applies the complete production overlay to these raw bytes.
This fixture is source evidence, never a real Android or Apple build.
Apple version controls execute only the actual patched version assignments
and `build_deb` variable prologue; they do not invoke Xcode, ldid or dpkg.

Upstream: https://github.com/SagerNet/sing-box-for-apple/blob/e232aaf22d6d68773196ffc8e6e79684a6be717c/Jailbreak/package.sh
