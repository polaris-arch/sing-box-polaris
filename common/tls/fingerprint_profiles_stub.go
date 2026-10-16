//go:build !with_utls

package tls

func fingerprintProfiles() (bool, []FingerprintProfile, []string) {
	return false, []FingerprintProfile{}, []string{}
}
