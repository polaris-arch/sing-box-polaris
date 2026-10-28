package libbox

import (
	"errors"
	"testing"

	box "github.com/sagernet/sing-box"
)

type runtimePersistenceTestHandler struct {
	incarnation     string
	revision        int64
	digest, content string
	err             error
}

func (h *runtimePersistenceTestHandler) RuntimePersistenceMode() string {
	return "exact_configuration_file"
}

func (h *runtimePersistenceTestHandler) PersistRuntimeConfiguration(incarnation string, revision int64, digest, content string) error {
	h.incarnation, h.revision, h.digest, h.content = incarnation, revision, digest, content
	return h.err
}

func TestRuntimeHostPersistenceCapturesExactOwnerAndError(t *testing.T) {
	failure := errors.New("owner revoked")
	old := &runtimePersistenceTestHandler{err: failure}
	next := new(runtimePersistenceTestHandler)
	persist := runtimeHostPersistence(old, "exact_configuration_file")
	identity := box.RuntimeIdentity{Incarnation: "run-one", Revision: 2, EffectiveDigest: "digest"}
	content := []byte("effective")
	if err := persist(identity, content); !errors.Is(err, failure) {
		t.Fatal("owner failure acknowledged durable")
	}
	content[0] = 'x'
	if old.content != "effective" || old.incarnation != "run-one" || old.revision != 2 || old.digest != "digest" || next.content != "" {
		t.Fatal("owner identity or content escaped")
	}
}

func TestRuntimeRegenerationRequiresSeparateAppAcknowledgement(t *testing.T) {
	handler := new(runtimePersistenceTestHandler)
	err := runtimeHostPersistence(handler, "app_authoritative_regeneration")(box.RuntimeIdentity{Incarnation: "run", Revision: 1}, []byte("effective"))
	var required *box.RuntimeOwnerAcknowledgementRequiredError
	if !errors.As(err, &required) || required.Mode != "app_authoritative_regeneration" || handler.content != "effective" {
		t.Fatal("provider reload falsely acknowledged durable")
	}
}
