package build_shared

import (
	"encoding/hex"
	"os/exec"
	"strings"
)

func LinkerFlags(version string, debug bool) string {
	flags := []string{
		"-X github.com/sagernet/sing-box/constant.Version=" + version,
		"-X runtime.godebugDefault=multipathtcp=0,tlssha1=1",
		"-checklinkname=0",
	}
	if revision := cleanSourceRevision(); revision != "" {
		flags = append(flags, "-X github.com/sagernet/sing-box/constant.SourceRevision="+revision)
	}
	if !debug {
		flags = append(flags, "-s", "-w", "-buildid=")
	}
	return strings.Join(flags, " ")
}

// Suppress a source claim for dirty, unpacked or non-Git builds.
func cleanSourceRevision() string {
	status, err := exec.Command("git", "status", "--porcelain").Output()
	if err != nil || strings.TrimSpace(string(status)) != "" {
		return ""
	}
	raw, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return ""
	}
	revision := strings.TrimSpace(string(raw))
	decoded, err := hex.DecodeString(revision)
	if err != nil || len(decoded) != 20 || revision != strings.ToLower(revision) {
		return ""
	}
	return revision
}
