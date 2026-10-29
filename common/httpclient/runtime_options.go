package httpclient

import (
	"errors"
	"runtime"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// ValidateRuntimeOptions is a pure build/variant check shared by eligibility
// and construction. A registered platform stub is never a usable transport.
func ValidateRuntimeOptions(options option.HTTPClientOptions) error {
	if options.Tag != "" {
		return nil // The receiving manager validates and captures the definition.
	}
	switch options.Engine {
	case "", C.TLSEngineGo:
		if options.Version < 0 || options.Version > 3 {
			return errors.New("unsupported HTTP version")
		}
		if options.Version == 3 && !C.WithQUIC {
			return errors.New("HTTP/3 is unavailable in this build")
		}
	case C.TLSEngineApple:
		if runtime.GOOS != "darwin" || !C.CGO_ENABLED {
			return errors.New("apple HTTP is unavailable in this build")
		}
		if (options.Version != 0 && options.Version != 2) || options.DisableVersionFallback {
			return errors.New("apple HTTP requires automatic HTTP/2 with version fallback")
		}
	default:
		return errors.New("unsupported HTTP engine")
	}
	return nil
}
