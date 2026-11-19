package option

// WindowsDirectoryEmptyStandaloneVersion is accepted only by the protected
// standalone stdin launch with an empty Tailscale inventory.
const WindowsDirectoryEmptyStandaloneVersion = 2

// A Windows launch envelope opts into the separately mapped cooperative domain.
// It does not attest executable identity; the host still validates native birth.
// Old strict decoders reject this field instead of silently using managed paths.
type WindowsDirectoryOptions struct {
	Version        int    `json:"version"`
	Root           string `json:"root"`
	RunNonce       string `json:"run_nonce"`
	ExpectedSource string `json:"expected_source"`
}
