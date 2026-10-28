# Pinned sing UDP session ownership patch

Upstream: github.com/sagernet/sing, commit 6f21f2425a959912c37d2ef43d61e2a663315dea, pristine tree 911a1eac17720546561224688ead8aa301a6d9b4.
The module version remains unchanged. The module root replacement is required for normal deterministic Go builds: replacing only common/udpnat while the parent sing module still owns that package gives overlapping module/package ownership. No module cache mutation is used.

Pristine carrier: 349 files / 977000 bytes. Patched carrier: 350 files / 982366 bytes. 348 files unchanged; one production file common/udpnat/service.go patched and one focused test added. LICENSE, go.mod and go.sum are exact upstream bytes. The pristine Git blob/SHA manifest and postimage manifest distinguish carrier source from owned patches.

The optional owned-context hook reserves before session creation and goroutine dispatch, releases loaded-session transient reservations immediately, and retains new-session ownership through handler/error/close/cache-removal terminal tail. Legacy handlers do not enter the hook. New fixtures are authored, not executed.
