# Pinned client packaging source fixture

Exact unmodified `gradle.properties` from SagerNet/sing-box-for-android commit `ae93152f21457723af77d144f28c1f7be7362aec`.
Git blob `e091da284e14b9acdc75e21602579d5799493dcb`; SHA256 `8757cf68af1e1684d6b3a5e77fb97541af940293f4fc989155313df6bfbe53b1`.
The adjacent LICENSE is the original notice from that revision.

The regression applies the complete production overlay to these raw bytes.
This fixture is source evidence, never a real Android or Apple build.
Apple version controls execute only the actual patched version assignments
and `build_deb` variable prologue; they do not invoke Xcode, ldid or dpkg.

Upstream: https://github.com/SagerNet/sing-box-for-android/blob/ae93152f21457723af77d144f28c1f7be7362aec/gradle.properties
