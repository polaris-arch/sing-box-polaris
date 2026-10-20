# fswatch failed-Start cleanup correction

The module replacement preserves github.com/sagernet/fswatch v0.1.2, upstream commit 97bbfafb2e505c88287bbd9f06a67639395fc3f5 and its MIT license. Only watcher.go production code changes: an Add failure closes the unpublished fsnotify watcher exactly once, and a failed Close remains an explicit incomplete-cleanup error carrying both causes. The companion three deterministic tests use injected Add/Close outcomes. No watcher redesign or module dependency upgrade is included.

The six original files are stored with .txt suffixes to avoid introducing an executable evidence module; upstream-files.json preserves original paths, Git blob identities and byte hashes. third_party/fswatch contains the same six files plus the cleanup test, with only watcher.go patched. fswatch-failed-start.patch and fswatch-replacement.json record the exact delta and final bytes.

Imports remain unchanged. The root replacement also applies to transitive consumers, including sing-tun, when built under the root module. The standalone selected-module CI queue runs this module and requires all three cleanup regression names. This is authored source coverage, not an executed validation result. No default HTTP2 implementation or Go version is changed.
