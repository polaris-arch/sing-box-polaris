package libbox

import (
	"errors"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
)

type nativeTunBindingFixture struct {
	version     int32
	allocations int
	session     *nativeTunBindingSessionFixture
	options     TunOptions
}

func (p *nativeTunBindingFixture) RuntimeTunVersion() int32 { return p.version }
func (p *nativeTunBindingFixture) NewTunSession(options TunOptions, previous RuntimeTunSession, receipt *RuntimeTunReceipt) (RuntimeTunSession, error) {
	p.allocations++
	p.options = options
	p.session = &nativeTunBindingSessionFixture{owner: receipt.OwnerID(), receipt: receipt, previous: previous}
	return p.session, nil
}

type nativeTunBindingSessionFixture struct {
	owner                     string
	receipt                   *RuntimeTunReceipt
	previous                  RuntimeTunSession
	prepares, aborts, retires int
	panicPrepare              bool
	failAbort                 bool
}

func (s *nativeTunBindingSessionFixture) OwnerID() string { return s.owner }
func (s *nativeTunBindingSessionFixture) Prepare() error {
	s.prepares++
	if s.panicPrepare {
		panic("native Prepare")
	}
	return nil
}
func (*nativeTunBindingSessionFixture) FileDescriptor() int32 { return -1 }
func (*nativeTunBindingSessionFixture) Validate() error       { return nil }
func (s *nativeTunBindingSessionFixture) Abort() error {
	s.aborts++
	if s.failAbort {
		return errors.New("NE callback still unjoined")
	}
	return nil
}
func (s *nativeTunBindingSessionFixture) Retire() error { s.retires++; return nil }

func TestNativeTunRegistrationIsActualOptionalVersionAndFreezesBeforeInitialize(t *testing.T) {
	w := &platformInterfaceWrapper{}
	server := &CommandServer{platformWrapper: w}
	bad := &nativeTunBindingFixture{version: 2}
	if err := server.SetRuntimeTunPlatform(bad); err == nil {
		t.Fatal("unknown native ABI admitted")
	}
	if w.RuntimeTunVersion() != 0 || bad.allocations != 0 {
		t.Fatal("inventory caused native effects")
	}
	platform := &nativeTunBindingFixture{version: 1}
	if err := server.SetRuntimeTunPlatform(platform); err != nil {
		t.Fatal(err)
	}
	if err := server.SetRuntimeTunPlatform(platform); err == nil {
		t.Fatal("original bridge replaced")
	}
	frozen := &CommandServer{platformWrapper: &platformInterfaceWrapper{tunFrozen: true}}
	if err := frozen.SetRuntimeTunPlatform(platform); err == nil {
		t.Fatal("late bridge replaced a live Box owner")
	}
	if platform.allocations != 0 {
		t.Fatal("registration touched native device")
	}
}

func TestNativeTunBindingRetainsReceiptAndFullExistingOptionsWithoutPrematurePrepare(t *testing.T) {
	p := &nativeTunBindingFixture{version: 1}
	w := &platformInterfaceWrapper{runtimeTunPlatform: p}
	receipt, err := adapter.NewRuntimeTunReceipt()
	if err != nil {
		t.Fatal(err)
	}
	session, err := w.NewRuntimeTunSession(&tun.Options{MTU: 1600, IncludePackage: []string{"example.app"}}, option.TunPlatformOptions{}, nil, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if p.session.prepares != 0 || p.options.GetMTU() != 1600 || !p.options.GetIncludePackage().HasNext() {
		t.Fatal("allocation dropped options or performed native Prepare")
	}
	if err = session.Prepare(); err != nil {
		t.Fatal(err)
	}
	if p.session.receipt.Published() {
		t.Fatal("native Prepare published graph")
	}
	receipt.Publish()
	if !p.session.receipt.Published() {
		t.Fatal("native receipt did not observe concrete Core publication")
	}
	if err = session.Retire(); err != nil {
		t.Fatal(err)
	}
	if err = session.Retire(); err != nil || p.session.retires != 1 {
		t.Fatal("duplicate native retirement", err)
	}
}

func TestNativeTunUnknownAbortBlocksNewAndLegacyOperations(t *testing.T) {
	p := &nativeTunBindingFixture{version: 1}
	w := &platformInterfaceWrapper{runtimeTunPlatform: p}
	receipt, err := adapter.NewRuntimeTunReceipt()
	if err != nil {
		t.Fatal(err)
	}
	session, err := w.NewRuntimeTunSession(&tun.Options{MTU: 1500}, option.TunPlatformOptions{}, nil, receipt)
	if err != nil {
		t.Fatal(err)
	}
	p.session.failAbort = true
	if err = session.Abort(); err == nil {
		t.Fatal("unknown cleanup erased")
	}
	if err = session.Abort(); err == nil || p.session.aborts != 1 {
		t.Fatal("unknown owner retried", err)
	}
	if w.RuntimeTunVersion() != 0 {
		t.Fatal("quarantined owner advertised available")
	}
	another, err := adapter.NewRuntimeTunReceipt()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.NewRuntimeTunSession(&tun.Options{MTU: 1500}, option.TunPlatformOptions{}, nil, another); err == nil {
		t.Fatal("new native operation passed quarantine")
	}
	if _, err = w.OpenInterface(&tun.Options{}, option.TunPlatformOptions{}); err == nil {
		t.Fatal("registered quarantined bridge fell back to legacy OpenTun")
	}
	if p.allocations != 1 {
		t.Fatal("unknown cleanup authorized new allocation")
	}
}

func TestNativeTunPreparePanicRetainsQuarantineAndSkipsFurtherNativeCleanup(t *testing.T) {
	p := &nativeTunBindingFixture{version: 1}
	w := &platformInterfaceWrapper{runtimeTunPlatform: p}
	receipt, err := adapter.NewRuntimeTunReceipt()
	if err != nil {
		t.Fatal(err)
	}
	session, err := w.NewRuntimeTunSession(&tun.Options{MTU: 1500}, option.TunPlatformOptions{}, nil, receipt)
	if err != nil {
		t.Fatal(err)
	}
	p.session.panicPrepare = true
	panicked := false
	func() { defer func() { panicked = recover() != nil }(); _ = session.Prepare() }()
	if !panicked || w.RuntimeTunVersion() != 0 {
		t.Fatal("native panic escaped quarantine")
	}
	if err = session.Abort(); err == nil || p.session.aborts != 0 {
		t.Fatal("unknown panic authorized another native operation", err)
	}
}
