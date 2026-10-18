package libbox

import (
	"encoding/json"
	"errors"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

// NewManagedStrictCommandServer is a native capability constructor. Its root
// must come from the platform's verified AppGroup URL, never decoded config.
// No service may be constructed until the host completes the original-owner
// source handshake and explicitly activates this same command server.
func NewManagedStrictCommandServer(handler CommandServerHandler, platformInterface PlatformInterface, verifiedAppGroupRoot, ownerNonce string) (*CommandServer, error) {
	domain, err := adapter.NewTailscaleDirectoryDomain(verifiedAppGroupRoot, ownerNonce)
	if err != nil {
		return nil, err
	}
	if err = domain.SetFailureHandler(func(error) error { return poisonTailscaleDirectoryDomain(domain.PhysicalRoot()) }); err != nil {
		return nil, err
	}
	return newCommandServer(handler, platformInterface, false, true, domain)
}

func directorySourceIdentityValid(identity string) bool {
	if len(identity) != 40 {
		return false
	}
	for _, c := range identity {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (s *CommandServer) ExportTailscaleDirectoryCapability() string {
	d := s.directoryDomain
	if d == nil {
		return `{ "contractVersion":"polaris-ts-directory-capability-v1", "participating":false }`
	}
	s.commandAccess.Lock()
	closing := s.commandIsClosing
	s.commandAccess.Unlock()
	value := struct {
		ContractVersion string `json:"contractVersion"`
		SourceABI       string `json:"sourceABI"`
		SourceIdentity  string `json:"sourceIdentity"`
		ManagedRoot     string `json:"managedRoot"`
		LogicalRoot     string `json:"logicalRoot"`
		OwnerNonce      string `json:"ownerNonce"`
		Participating   bool   `json:"participating"`
	}{"polaris-ts-directory-capability-v1", "polaris-g4-directory-v1", C.DirectoryRetirementSourceIdentity, d.PhysicalRoot(), d.LogicalRoot(), d.OwnerNonce(), !closing && tailscaleDirectoryDomainSupported && directorySourceIdentityValid(C.DirectoryRetirementSourceIdentity) && d.Failure() == nil}
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func (s *CommandServer) ActivateTailscaleDirectoryDomain(ownerNonce, expectedSourceIdentity string) error {
	s.commandAccess.Lock()
	defer s.commandAccess.Unlock()
	d := s.directoryDomain
	if s.commandIsClosing || d == nil || ownerNonce != d.OwnerNonce() || !tailscaleDirectoryDomainSupported || !directorySourceIdentityValid(expectedSourceIdentity) || expectedSourceIdentity != C.DirectoryRetirementSourceIdentity {
		return errors.New("managed directory original-owner/source handshake mismatch")
	}
	// All instance construction gates on Activated, so Prepared has no prior run.
	return d.Activate()
}
