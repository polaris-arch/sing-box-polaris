package dialer

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/service"
)

type bindingTestPlatform struct {
	adapter.PlatformInterface
	calls int
	fd    int
	name  string
	err   error
}

func (p *bindingTestPlatform) BindInterfaceControl(fd int, name string) error {
	p.calls++
	p.fd, p.name = fd, name
	return p.err
}

type bindingTestRawConn struct{ err error }

func (c bindingTestRawConn) Control(f func(uintptr)) error {
	if c.err != nil {
		return c.err
	}
	f(42)
	return nil
}

func (bindingTestRawConn) Read(func(uintptr) bool) error  { panic("unused") }
func (bindingTestRawConn) Write(func(uintptr) bool) error { panic("unused") }

func TestPlatformInterfaceBindingTCPUDPAndFailures(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			p := &bindingTestPlatform{}
			bind, err := platformBindInterfaceControl(p, "wlan0")
			if err != nil {
				t.Fatal(err)
			}
			if err = bind(network, "synthetic", bindingTestRawConn{}); err != nil {
				t.Fatal(err)
			}
			if p.calls != 1 || p.fd != 42 || p.name != "wlan0" {
				t.Fatalf("binding not forwarded: %#v", p)
			}
			p.err = errors.New("network disappeared")
			if err = bind(network, "synthetic", bindingTestRawConn{}); !errors.Is(err, p.err) {
				t.Fatalf("binding failure was hidden: %v", err)
			}
			rawErr := errors.New("descriptor closed")
			if err = bind(network, "synthetic", bindingTestRawConn{rawErr}); !errors.Is(err, rawErr) {
				t.Fatalf("RawConn failure was hidden: %v", err)
			}
			if p.calls != 2 {
				t.Fatal("RawConn failure still called binder")
			}
		})
	}
	for _, platform := range []adapter.PlatformInterface{nil, struct{ adapter.PlatformInterface }{}} {
		if bind, err := platformBindInterfaceControl(platform, "wlan0"); err == nil || bind != nil {
			t.Fatal("missing platform binder accepted")
		}
	}
}

type bindingTestNetworkManager struct{ adapter.NetworkManager }

func (bindingTestNetworkManager) InterfaceFinder() control.InterfaceFinder {
	return control.NewDefaultInterfaceFinder()
}

func (bindingTestNetworkManager) DefaultOptions() adapter.NetworkOptions {
	return adapter.NetworkOptions{BindInterface: "lo"}
}

func (bindingTestNetworkManager) AutoRedirectOutputMarkFunc() control.Func { return nil }

func TestNamedInterfaceBindingPreservesNonAndroidAndAutomaticDialers(t *testing.T) {
	if C.IsAndroid {
		t.Skip("host regression")
	}
	p := &bindingTestPlatform{err: errors.New("must not be called")}
	ctx := service.ContextWith[adapter.PlatformInterface](context.Background(), p)
	for _, options := range []option.DialerOptions{{}, {BindInterface: "lo"}} {
		dialer, err := NewDefault(ctx, options)
		if err != nil {
			t.Fatal(err)
		}
		_ = dialer.dialer4.Control("tcp4", "127.0.0.1:443", bindingTestRawConn{})
	}
	ctx = service.ContextWith[adapter.NetworkManager](ctx, bindingTestNetworkManager{})
	dialer, err := NewDefault(ctx, option.DialerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_ = dialer.dialer4.Control("tcp4", "127.0.0.1:443", bindingTestRawConn{})
	if p.calls != 0 {
		t.Fatal("non-Android dialer called Android platform binder")
	}
}

// Host behavior tests cannot change GOOS. Inspect the actual constructor AST to ensure both
// explicit and default choices attach the same binder to TCP dialing and UDP listening.
func TestNamedInterfaceBindingConstructorWiring(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "default.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var branches int
	ast.Inspect(f, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		var found bool
		for _, stmt := range block.List {
			assign, ok := stmt.(*ast.AssignStmt)
			if !ok {
				continue
			}
			for _, rhs := range assign.Rhs {
				call, ok := rhs.(*ast.CallExpr)
				if ok {
					id, ok := call.Fun.(*ast.Ident)
					found = found || ok && id.Name == "bindInterfaceControl"
				}
			}
		}
		if !found {
			return true
		}
		branches++
		controls := map[string]bool{}
		for _, stmt := range block.List {
			assign, ok := stmt.(*ast.AssignStmt)
			if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
				continue
			}
			sel, ok := assign.Lhs[0].(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Control" {
				continue
			}
			owner, ok := sel.X.(*ast.Ident)
			call, callOK := assign.Rhs[0].(*ast.CallExpr)
			if !ok || !callOK || len(call.Args) != 2 {
				continue
			}
			binder, ok := call.Args[1].(*ast.Ident)
			if ok && binder.Name == "bindFunc" {
				controls[owner.Name] = true
			}
		}
		if !controls["dialer"] || !controls["listenConfig"] {
			t.Error("named binding not attached to both TCP and UDP")
		}
		return true
	})
	if branches != 2 {
		t.Fatalf("expected explicit and default bind paths, got %d", branches)
	}
}

var _ syscall.RawConn = bindingTestRawConn{}
