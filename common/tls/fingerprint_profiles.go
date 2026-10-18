//go:build with_utls

package tls

import utls "github.com/refraction-networking/utls"

type fingerprintProfile struct {
	ID, DisplayName string
	Hello           utls.ClientHelloID
}

var utlsProfiles = []fingerprintProfile{
	{"chrome", "Chrome (Auto)", utls.HelloChrome_Auto},
	{"chrome_155", "Chrome 155", utls.HelloChrome_155},
	{"chrome_133", "Chrome 133", utls.HelloChrome_133},
	{"firefox", "Firefox (Auto)", utls.HelloFirefox_Auto},
	{"firefox_148", "Firefox 148", utls.HelloFirefox_148},
	{"firefox_120", "Firefox 120", utls.HelloFirefox_120},
	{"edge", "Edge (Auto)", utls.HelloEdge_Auto},
	{"safari", "Safari (Auto)", utls.HelloSafari_Auto},
	{"safari_26_3", "Safari 26.3", utls.HelloSafari_26_3},
	{"safari_16_0", "Safari 16.0", utls.HelloSafari_16_0},
	{"360", "360 (Auto)", utls.Hello360_Auto},
	{"qq", "QQ (Auto)", utls.HelloQQ_Auto},
	{"ios", "iOS (Auto)", utls.HelloIOS_Auto},
	{"android", "Android 11 OkHttp", utls.HelloAndroid_11_OkHttp},
}
var utlsLegacyAliases = []string{"chrome_psk", "chrome_psk_shuffle", "chrome_padding_psk_shuffle", "chrome_pq", "chrome_pq_psk"}

func profileCapabilities(id, displayName, selection string, hello utls.ClientHelloID) FingerprintProfile {
	p := FingerprintProfile{ID: id, DisplayName: displayName, Client: hello.Client, TemplateVersion: hello.Version, Selection: selection}
	if id == "randomized" {
		return p
	}
	if spec, err := utls.UTLSIdToSpec(hello); err == nil {
		offers := false
		for _, extension := range spec.Extensions {
			if curves, ok := extension.(*utls.SupportedCurvesExtension); ok {
				for _, curve := range curves.Curves {
					if curve == utls.X25519MLKEM768 {
						offers = true
					}
				}
			}
		}
		p.TemplateOffersX25519MLKEM768 = &offers
	}
	return p
}

func fingerprintProfiles() (bool, []FingerprintProfile, []string) {
	profiles := make([]FingerprintProfile, 0, len(utlsProfiles)+2)
	profiles = append(profiles, profileCapabilities("random", "Random browser", "process-browser", randomFingerprint), profileCapabilities("randomized", "Randomized ClientHello", "process-seeded-generator", randomizedFingerprint))
	for _, p := range utlsProfiles {
		profiles = append(profiles, profileCapabilities(p.ID, p.DisplayName, "profile", p.Hello))
	}
	return true, profiles, append([]string(nil), utlsLegacyAliases...)
}
