package adapter

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestDirectoryDomainRequiresActivationAndFailureIsSticky(t *testing.T) {
	base := filepath.Join(t.TempDir(), "polaris")
	d, err := NewTailscaleDirectoryDomain(base, "native-owner")
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(base, "tailscale", "node")
	in := TailscaleDirectoryMappingInput{state, filepath.Join(state, "Taildrop", "inbox")}
	if _, err := NewTailscaleDirectoryMapping(d, []TailscaleDirectoryMappingInput{in}); err == nil {
		t.Fatal("inactive domain authorized mapping")
	}
	if err := d.SetFailureHandler(func(error) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := d.Activate(); err != nil {
		t.Fatal(err)
	}
	m, err := NewTailscaleDirectoryMapping(d, []TailscaleDirectoryMappingInput{in})
	if err != nil {
		t.Fatal(err)
	}
	physical, taildrop, ok := m.Resolve(in.StateDirectory, in.TaildropDirectory)
	if !ok || physical != filepath.Join(base, "tailscale-g4-v1", "node") || taildrop != filepath.Join(physical, "Taildrop", "inbox") {
		t.Fatal("incorrect mapping")
	}
	if _, _, ok := m.Resolve(in.StateDirectory, filepath.Join(state, "other")); ok {
		t.Fatal("unvalidated pair authorized")
	}
	ctx := ContextWithTailscaleDirectoryDomain(context.Background(), d)
	ctx = ContextWithTailscaleDirectoryMapping(ctx, m)
	if TailscaleDirectoryDomainFromContext(ctx) != d || TailscaleDirectoryMappingFromContext(ctx).Domain() != d {
		t.Fatal("capability identity changed")
	}
	failure := errors.New("uncertain owner")
	d.Fail(failure)
	d.Fail(errors.New("later failure"))
	if d.Active() || d.Activate() == nil || d.Failure() != failure {
		t.Fatal("failure was reset")
	}
	if _, _, ok := m.Resolve(in.StateDirectory, in.TaildropDirectory); ok {
		t.Fatal("old plan survived domain failure")
	}
}

func TestDirectoryMappingRejectsWholeInvalidSet(t *testing.T) {
	base := filepath.Join(t.TempDir(), "polaris")
	state := filepath.Join(base, "tailscale", "node")
	good := TailscaleDirectoryMappingInput{state, filepath.Join(state, "Taildrop")}
	cases := []TailscaleDirectoryMappingInput{
		{state, ""}, {state, state}, {state, filepath.Join(base, "outside")},
		{filepath.Join(state, "nested"), filepath.Join(state, "nested", "Taildrop")},
		{filepath.Join(base, "tailscale-g4-v1", "foreign"), filepath.Join(base, "tailscale-g4-v1", "foreign", "Taildrop")},
		good,
	}
	for _, invalid := range cases {
		d, err := NewTailscaleDirectoryDomain(base, "owner")
		if err != nil {
			t.Fatal(err)
		}
		if err := d.SetFailureHandler(func(error) error { return nil }); err != nil {
			t.Fatal(err)
		}
		if err := d.Activate(); err != nil {
			t.Fatal(err)
		}
		m, err := NewTailscaleDirectoryMapping(d, []TailscaleDirectoryMappingInput{good, invalid})
		if err == nil || m != nil || d.Active() || d.Failure() == nil {
			t.Fatal("partial plan escaped invalid census")
		}
	}
}

func TestZeroDirectoryDomainCannotActivate(t *testing.T) {
	var d TailscaleDirectoryDomain
	if d.Activate() == nil || d.Active() {
		t.Fatal("zero domain activated")
	}
	if _, err := NewTailscaleDirectoryDomain("relative", "owner"); err == nil {
		t.Fatal("relative trusted root accepted")
	}
	if _, err := NewTailscaleDirectoryDomain(t.TempDir(), ""); err == nil {
		t.Fatal("empty native owner accepted")
	}
}

func TestDomainFailurePersistenceIsJoinedAndNeverRetried(t *testing.T) {
	d, err := NewTailscaleDirectoryDomain(filepath.Join(t.TempDir(), "polaris"), "owner")
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	closeError := errors.New("unsafe marker close failed")
	calls := 0
	if err := d.SetFailureHandler(func(error) error {
		calls++
		close(entered)
		<-release
		return closeError
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.Activate(); err != nil {
		t.Fatal(err)
	}
	if d.Activate() == nil {
		t.Fatal("activation was repeatable")
	}
	done := make(chan error, 1)
	go func() { done <- d.Fail(errors.New("invalid profile")) }()
	<-entered
	if d.Active() || !d.Activated() {
		t.Fatal("proof or admission state wrong during durable revocation")
	}
	select {
	case <-done:
		t.Fatal("legacy admission preceded marker close")
	default:
	}
	close(release)
	if err := <-done; err != closeError {
		t.Fatal("close failure lost")
	}
	if d.Fail(errors.New("later")) != closeError || d.FailurePersistenceError() != closeError || calls != 1 {
		t.Fatal("uncertain persistence was retried or erased")
	}
}
