package libbox

import (
	"errors"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

type runtimeTailscalePlatformFixture struct {
	version              int32
	validations, claims  int
	claimErr, releaseErr error
	released             *RuntimeTailscaleScope
	acquired             bool
}

func (p *runtimeTailscalePlatformFixture) RuntimeTailscaleVersion() int32 { return p.version }
func (p *runtimeTailscalePlatformFixture) ValidateRuntimeTailscale(tag, state, taildrop string) bool {
	p.validations++
	return tag == "expected" && state == "/state" && taildrop == "/taildrop"
}

func (p *runtimeTailscalePlatformFixture) ClaimRuntimeTailscale(*RuntimeTailscaleScope) (bool, error) {
	p.claims++
	return p.claimErr == nil, p.claimErr
}

func (p *runtimeTailscalePlatformFixture) ReleaseRuntimeTailscale(scope *RuntimeTailscaleScope, acquired bool) error {
	p.released, p.acquired = scope, acquired
	return p.releaseErr
}

func TestRuntimeTailscaleBridgeIsAndroidMainOwnerOptIn(t *testing.T) {
	native := &runtimeTailscalePlatformFixture{version: 1}
	for _, test := range []struct {
		name   string
		server *CommandServer
	}{
		{"desktop", &CommandServer{platformWrapper: &platformInterfaceWrapper{}}},
		{"transient", &CommandServer{transient: true, platformWrapper: &platformInterfaceWrapper{androidTailscaleHost: true}}},
		{"initialized", &CommandServer{platformWrapper: &platformInterfaceWrapper{androidTailscaleHost: true, runtimeTailscaleFrozen: true}}},
		{"closing", &CommandServer{commandIsClosing: true, platformWrapper: &platformInterfaceWrapper{androidTailscaleHost: true}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.server.SetRuntimeTailscalePlatform(native); err == nil {
				t.Fatal("binding accepted outside the original uninitialized Android main command owner")
			}
		})
	}

	scope := adapter.RuntimeTailscaleWriterScope{
		ResourceID: adapter.RuntimeResourceID{Incarnation: "original", Sequence: 7},
		Generation: 1, Binding: adapter.TailscaleStoreRunBinding{RunNonce: "birth", ConfigDigest: "config"},
		Tag: "expected", Directories: adapter.RuntimeTailscaleDirectories{State: "/state", Taildrop: "/taildrop"},
	}
	w := &platformInterfaceWrapper{androidTailscaleHost: true}
	server := &CommandServer{platformWrapper: w}
	if w.ValidateRuntimeTailscaleWriter(scope.Tag, scope.Directories) {
		t.Fatal("unbound legacy platform allowed a warm writer")
	}
	if err := server.SetRuntimeTailscalePlatform(&runtimeTailscalePlatformFixture{version: 2}); err == nil {
		t.Fatal("unknown callback version was accepted")
	}
	if err := server.SetRuntimeTailscalePlatform(native); err != nil {
		t.Fatal(err)
	}
	if err := server.SetRuntimeTailscalePlatform(native); err == nil {
		t.Fatal("live original registration could be replaced")
	}
	if !w.ValidateRuntimeTailscaleWriter(scope.Tag, scope.Directories) || native.validations != 1 || native.claims != 0 {
		t.Fatal("Plan validation reserved the writer")
	}
	if ok, err := w.ClaimRuntimeTailscaleWriter(scope); err != nil || !ok {
		t.Fatal("native owner failed acquisition", err)
	}

	// A separate unknown acquisition quarantines later admissions. It cannot
	// prevent valid cleanup of an earlier, independently acknowledged claim.
	native.claimErr = errors.New("fixture opaque failure")
	other := scope
	other.ResourceID.Sequence++
	if ok, err := w.ClaimRuntimeTailscaleWriter(other); err == nil || ok || w.ValidateRuntimeTailscaleWriter(scope.Tag, scope.Directories) {
		t.Fatal("unknown callback result did not quarantine later admissions")
	}
	if err := w.ReleaseRuntimeTailscaleWriter(scope, true); err != nil || native.released.scope != scope || !native.acquired {
		t.Fatal("cleanup lost the earlier exact owner", err)
	}
}
