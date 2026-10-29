package httpclient

import (
	"context"
	"net/http"
	"runtime"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func TestRuntimeHTTPVariantEligibilityMatchesBuild(t *testing.T) {
	for _, test := range []struct {
		options   option.HTTPClientOptions
		supported bool
	}{
		{option.HTTPClientOptions{Version: 1}, true},
		{option.HTTPClientOptions{Version: 2}, true},
		{option.HTTPClientOptions{Version: 3}, C.WithQUIC},
		{option.HTTPClientOptions{Version: 4}, false},
		{option.HTTPClientOptions{Engine: "future"}, false},
		{option.HTTPClientOptions{Engine: "apple"}, runtime.GOOS == "darwin" && C.CGO_ENABLED},
		{option.HTTPClientOptions{Engine: "apple", Version: 1}, false},
		{option.HTTPClientOptions{Engine: "apple", Version: 3}, false},
		{option.HTTPClientOptions{Engine: "apple", DisableVersionFallback: true}, false},
	} {
		if (ValidateRuntimeOptions(test.options) == nil) != test.supported {
			t.Fatalf("build/variant mismatch: %+v", test)
		}
	}
}

func TestRuntimeHTTPDuplicateAndEmptyDefinitionsFailBeforeTransportConstruction(t *testing.T) {
	for _, clients := range [][]option.HTTPClient{
		{{Tag: "same"}, {Tag: "same"}}, {{Tag: ""}},
	} {
		manager := NewManager(context.Background(), log.NewNOPFactory().Logger(), clients, "")
		defer manager.RuntimeCloseAndWait()
		called := false
		err := manager.PrepareRuntime(func() (*ManagedTransport, error) { called = true; return nil, nil })
		if err == nil || called || len(manager.managedTransports) != 0 {
			t.Fatal("invalid definitions constructed a transport", err)
		}
	}
}

type runtimeRecursiveHTTP struct {
	target *ManagedTransport
	calls  int
}

func (r *runtimeRecursiveHTTP) RoundTrip(request *http.Request) (*http.Response, error) {
	r.calls++
	return r.target.RoundTrip(request)
}
func (*runtimeRecursiveHTTP) Close() error          { return nil }
func (*runtimeRecursiveHTTP) CloseIdleConnections() {}

func TestRuntimeHTTPNamedManagerSelfReferenceIsRejectedWithinOriginalEpoch(t *testing.T) {
	inner := &runtimeRecursiveHTTP{}
	managed := &ManagedTransport{tag: "same-tag", factory: func() (innerTransport, error) { return inner, nil }}
	inner.target = managed
	managed.epoch.Store(&transportEpoch{transport: inner})
	if err := managed.initializeRuntime(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer managed.RuntimeCloseAndWait()
	request, _ := http.NewRequest(http.MethodGet, "https://fixture.invalid", nil)
	if _, err := managed.RoundTrip(request); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatal("manager self-reference escaped request loop protection", err)
	}
	if inner.calls != 1 {
		t.Fatal("recursive transport was entered twice")
	}
}
