package badversion

import (
	"strconv"
	"strings"

	F "github.com/sagernet/sing/common/format"

	"golang.org/x/mod/semver"
)

type Version struct {
	Major                int
	Minor                int
	Patch                int
	Commit               string
	PreReleaseIdentifier string
	PreReleaseVersion    int
	// Preserve Polaris patch identity without ranking patches within an upstream series.
	preReleaseVersionString string
}

func (v Version) LessThan(anotherVersion Version) bool {
	return !v.GreaterThanOrEqual(anotherVersion)
}

func (v Version) LessThanOrEqual(anotherVersion Version) bool {
	return v.equal(anotherVersion) || anotherVersion.GreaterThan(v)
}

func (v Version) GreaterThanOrEqual(anotherVersion Version) bool {
	return v.equal(anotherVersion) || v.GreaterThan(anotherVersion)
}

func (v Version) equal(anotherVersion Version) bool {
	v.preReleaseVersionString = ""
	anotherVersion.preReleaseVersionString = ""
	return v == anotherVersion
}

func (v Version) GreaterThan(anotherVersion Version) bool {
	if v.Major > anotherVersion.Major {
		return true
	} else if v.Major < anotherVersion.Major {
		return false
	}
	if v.Minor > anotherVersion.Minor {
		return true
	} else if v.Minor < anotherVersion.Minor {
		return false
	}
	if v.Patch > anotherVersion.Patch {
		return true
	} else if v.Patch < anotherVersion.Patch {
		return false
	}
	if v.PreReleaseIdentifier == "" && anotherVersion.PreReleaseIdentifier != "" {
		return true
	} else if v.PreReleaseIdentifier != "" && anotherVersion.PreReleaseIdentifier == "" {
		return false
	}
	if v.PreReleaseIdentifier != "" && anotherVersion.PreReleaseIdentifier != "" {
		if v.PreReleaseIdentifier == anotherVersion.PreReleaseIdentifier {
			if v.PreReleaseVersion > anotherVersion.PreReleaseVersion {
				return true
			} else if v.PreReleaseVersion < anotherVersion.PreReleaseVersion {
				return false
			}
		}
		preReleaseIdentifier := parsePreReleaseIdentifier(v.PreReleaseIdentifier)
		anotherPreReleaseIdentifier := parsePreReleaseIdentifier(anotherVersion.PreReleaseIdentifier)
		if preReleaseIdentifier < anotherPreReleaseIdentifier {
			return true
		} else if preReleaseIdentifier > anotherPreReleaseIdentifier {
			return false
		}
	}
	return false
}

func parsePreReleaseIdentifier(identifier string) int {
	identifier = strings.TrimPrefix(identifier, "polaris-")
	if strings.HasPrefix(identifier, "rc") {
		return 1
	} else if strings.HasPrefix(identifier, "beta") {
		return 2
	} else if strings.HasPrefix(identifier, "alpha") {
		return 3
	}
	return 0
}

func (v Version) VersionString() string {
	return F.ToString(v.Major, ".", v.Minor, ".", v.Patch)
}

func (v Version) String() string {
	version := F.ToString(v.Major, ".", v.Minor, ".", v.Patch)
	if v.PreReleaseIdentifier != "" {
		number := F.ToString(v.PreReleaseVersion)
		if v.preReleaseVersionString != "" {
			number = v.preReleaseVersionString
		}
		version = F.ToString(version, "-", v.PreReleaseIdentifier, ".", number)
	}
	return version
}

func (v Version) BadString() string {
	version := F.ToString(v.Major, ".", v.Minor)
	if v.Patch > 0 {
		version = F.ToString(version, ".", v.Patch)
	}
	if v.PreReleaseIdentifier != "" {
		version = F.ToString(version, "-", v.PreReleaseIdentifier)
		if v.PreReleaseVersion > 0 {
			version = F.ToString(version, v.PreReleaseVersion)
		}
	}
	return version
}

func IsValid(versionName string) bool {
	return semver.IsValid("v" + versionName)
}

func Parse(versionName string) (version Version) {
	versionName = strings.TrimPrefix(versionName, "v")
	if strings.Contains(versionName, "-") {
		parts := strings.Split(versionName, "-")
		// Preserve the fork prerelease family without changing upstream commit suffix parsing.
		if len(parts) >= 3 && parts[1] == "polaris" {
			parts = []string{parts[0], "polaris-" + parts[2]}
		}
		versionName = parts[0]
		identifier := parts[1]
		if strings.Contains(identifier, ".") {
			identifierParts := strings.Split(identifier, ".")
			version.PreReleaseIdentifier = identifierParts[0]
			if len(identifierParts) >= 2 {
				version.PreReleaseVersion, _ = strconv.Atoi(identifierParts[1])
			}
			if (len(identifierParts) == 2 || len(identifierParts) == 3) &&
				(identifierParts[0] == "polaris-alpha" || identifierParts[0] == "polaris-beta" || identifierParts[0] == "polaris-rc") &&
				isCanonicalNumber(identifierParts[1]) && (len(identifierParts) == 2 || isCanonicalNumber(identifierParts[2])) {
				version.preReleaseVersionString = strings.Join(identifierParts[1:], ".")
			}
		} else {
			if strings.HasPrefix(identifier, "alpha") {
				version.PreReleaseIdentifier = "alpha"
				version.PreReleaseVersion, _ = strconv.Atoi(identifier[5:])
			} else if strings.HasPrefix(identifier, "beta") {
				version.PreReleaseIdentifier = "beta"
				version.PreReleaseVersion, _ = strconv.Atoi(identifier[4:])
			} else {
				version.Commit = identifier
			}
		}
	}
	versionElements := strings.Split(versionName, ".")
	versionLen := len(versionElements)
	if versionLen >= 1 {
		version.Major, _ = strconv.Atoi(versionElements[0])
	}
	if versionLen >= 2 {
		version.Minor, _ = strconv.Atoi(versionElements[1])
	}
	if versionLen >= 3 {
		version.Patch, _ = strconv.Atoi(versionElements[2])
	}
	return
}

// isCanonicalNumber does not narrow a valid identity to the machine integer range.
func isCanonicalNumber(value string) bool {
	if value == "" || len(value) > 1 && value[0] == '0' {
		return false
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}
