package box_test

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

// The construction scope only releases what constructors register in it, so
// constructors must not hold goroutines or file descriptors on their own
// before the component is started. These tests construct boxes from the
// default registries without starting them and compare both counts.

const leakTestConfig = `{
	"log": {"disabled": true},
	"dns": {
		"servers": [
			{"type": "local", "tag": "local"},
			{"type": "udp", "tag": "udp", "server": "192.0.2.1"},
			{"type": "tls", "tag": "tls", "server": "192.0.2.1"},
			{"type": "https", "tag": "https", "server": "192.0.2.1"},
			{"type": "fakeip", "tag": "fakeip", "inet4_range": "198.18.0.0/15"},
			{"type": "hosts", "tag": "hosts", "predefined": {"example.invalid": "192.0.2.2"}}
		]
	},
	"inbounds": [
		{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0},
		{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 0},
		{"type": "direct", "tag": "direct-in", "listen": "127.0.0.1", "listen_port": 0}
	],
	"outbounds": [
		{"type": "direct", "tag": "direct"},
		{"type": "block", "tag": "block"},
		{"type": "socks", "tag": "socks", "server": "192.0.2.1", "server_port": 1080},
		{"type": "http", "tag": "http", "server": "192.0.2.1", "server_port": 8080},
		{"type": "shadowsocks", "tag": "shadowsocks", "server": "192.0.2.1", "server_port": 8388, "method": "aes-128-gcm", "password": "password"},
		{"type": "trojan", "tag": "trojan", "server": "192.0.2.1", "server_port": 443, "password": "password", "tls": {"enabled": true, "server_name": "example.invalid"}},
		{"type": "vless", "tag": "vless", "server": "192.0.2.1", "server_port": 443, "uuid": "bf000d23-0752-40b4-affe-68f7707a9661", "tls": {"enabled": true, "server_name": "example.invalid"}, "transport": {"type": "ws"}},
		{"type": "vmess", "tag": "vmess", "server": "192.0.2.1", "server_port": 443, "uuid": "bf000d23-0752-40b4-affe-68f7707a9661", "transport": {"type": "grpc", "service_name": "service"}, "tls": {"enabled": true, "server_name": "example.invalid"}},
		{"type": "selector", "tag": "selector", "outbounds": ["direct", "socks"]},
		{"type": "urltest", "tag": "urltest", "outbounds": ["direct", "socks"]}
	],
	"route": {"final": "direct"},
	"experimental": {"cache_file": {"enabled": true, "path": "unused-cache.db"}}
}`

type leakProbeOutbound struct {
	outbound.Adapter
	adapter.Outbound
}

func (o *leakProbeOutbound) Type() string           { return o.Adapter.Type() }
func (o *leakProbeOutbound) Tag() string            { return o.Adapter.Tag() }
func (o *leakProbeOutbound) Network() []string      { return o.Adapter.Network() }
func (o *leakProbeOutbound) Dependencies() []string { return nil }

type leakProbe struct {
	file    *os.File
	release chan struct{}
}

func (p *leakProbe) close() {
	p.file.Close()
	close(p.release)
}

func leakTestContext(probe *leakProbe) context.Context {
	outboundRegistry := include.OutboundRegistry()
	// The probe acquires a file and a goroutine in its constructor and
	// registers neither, which is exactly what the leak check must detect.
	outbound.Register[struct{}](outboundRegistry, "leak-probe", func(context.Context, adapter.Router, log.ContextLogger, string, struct{}) (adapter.Outbound, error) {
		file, err := os.Open(os.DevNull)
		if err != nil {
			return nil, err
		}
		probe.file = file
		probe.release = make(chan struct{})
		go func() { <-probe.release }()
		return &leakProbeOutbound{Adapter: outbound.NewAdapter("leak-probe", "leak-probe", nil, nil)}, nil
	})
	return box.Context(context.Background(), include.InboundRegistry(), outboundRegistry, include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry(), include.CertificateProviderRegistry())
}

func leakTestOptions(t *testing.T, ctx context.Context, mutate func(*option.Options)) box.Options {
	t.Helper()
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(leakTestConfig))
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(&options)
	}
	return box.Options{Context: ctx, Options: options}
}

func openFiles(t *testing.T) int {
	t.Helper()
	if runtime.GOOS != "linux" {
		return 0
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// measureLeak reports how many goroutines and open files action left behind.
func measureLeak(t *testing.T, action func()) (goroutines int, files int) {
	t.Helper()
	runtime.GC()
	baseGoroutines, baseFiles := runtime.NumGoroutine(), openFiles(t)
	action()
	deadline := time.Now().Add(2 * time.Second)
	for {
		runtime.GC()
		goroutines, files = runtime.NumGoroutine()-baseGoroutines, openFiles(t)-baseFiles
		if goroutines <= 0 && files <= 0 || time.Now().After(deadline) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestUnstartedConstructionLeaksNothing(t *testing.T) {
	ctx := leakTestContext(&leakProbe{})
	goroutines, files := measureLeak(t, func() {
		instance, err, report := box.NewWithConstructionReport(leakTestOptions(t, ctx, nil))
		if err != nil {
			t.Fatal(err)
		}
		if !report.Attempted || report.CleanupError != nil {
			t.Fatalf("report = %+v", report)
		}
		err = instance.CloseWithResult()
		if err != nil {
			t.Fatal(err)
		}
	})
	if goroutines > 0 || files > 0 {
		t.Fatalf("construct and close left %d goroutines and %d open files", goroutines, files)
	}
}

func TestFailedConstructionLeaksNothing(t *testing.T) {
	ctx := leakTestContext(&leakProbe{})
	goroutines, files := measureLeak(t, func() {
		instance, err, report := box.NewWithConstructionReport(leakTestOptions(t, ctx, func(options *option.Options) {
			// Every other component is constructed before the duplicate is rejected.
			options.Outbounds = append(options.Outbounds, option.Outbound{Type: "block", Tag: "direct"})
		}))
		if instance != nil || err == nil {
			t.Fatalf("New = %v, %v; want duplicate tag failure", instance, err)
		}
		if !report.Attempted || report.CleanupError != nil {
			t.Fatalf("report = %+v", report)
		}
	})
	if goroutines > 0 || files > 0 {
		t.Fatalf("failed construction left %d goroutines and %d open files", goroutines, files)
	}
}

func TestLeakCheckDetectsUnregisteredConstructorResources(t *testing.T) {
	probe := &leakProbe{}
	ctx := leakTestContext(probe)
	goroutines, files := measureLeak(t, func() {
		instance, err := box.New(leakTestOptions(t, ctx, func(options *option.Options) {
			options.Outbounds = append(options.Outbounds, option.Outbound{Type: "leak-probe", Tag: "leak-probe", Options: &struct{}{}})
		}))
		if err != nil {
			t.Fatal(err)
		}
		err = instance.CloseWithResult()
		if err != nil {
			t.Fatal(err)
		}
	})
	if probe.file == nil {
		t.Fatal("leak probe was not constructed")
	}
	defer probe.close()
	if goroutines < 1 {
		t.Fatalf("leak check missed the probe goroutine: %d", goroutines)
	}
	if runtime.GOOS == "linux" && files < 1 {
		t.Fatalf("leak check missed the probe file: %d", files)
	}
}
