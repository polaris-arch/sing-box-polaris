package option

// A Windows launch envelope opts into the separately mapped cooperative domain.
// It does not attest executable identity; the host still validates native birth.
// Old strict decoders reject this field instead of silently using managed paths.
type WindowsDirectoryOptions struct {
 Version int `json:"version"`
 Root string `json:"root"`
 RunNonce string `json:"run_nonce"`
 ExpectedSource string `json:"expected_source"`
}
