package tor

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestRuntimeTorOverlapDefaultAppSettings(t *testing.T) {
	for _, options := range []option.TorOutboundOptions{
		{},
		{ExecutablePath: "/usr/bin/tor"},
		{Options: map[string]string{"Socks5Proxy": "ignored", "Socks5ProxyUsername": "ignored", "Socks5ProxyPassword": "ignored"}},
	} {
		if field, reason := RuntimeOverlapProblem(options); field != "" || reason != "" {
			t.Fatalf("private default process rejected: %s: %s", field, reason)
		}
	}
}

func TestRuntimeTorOverlapExclusiveConfiguration(t *testing.T) {
	cases := []struct {
		options option.TorOutboundOptions
		field   string
	}{
		{option.TorOutboundOptions{DataDirectory: "persistent"}, "data_directory"},
		{option.TorOutboundOptions{DataDirectory: "$TOR_STATE"}, "data_directory"},
		{option.TorOutboundOptions{ExtraArgs: []string{"--DataDirectory", "shared"}}, "extra_args"},
		{option.TorOutboundOptions{ExtraArgs: []string{"--ControlPort=9051"}}, "extra_args"},
		{option.TorOutboundOptions{ExtraArgs: []string{"-f", "external-torrc"}}, "extra_args"},
		{option.TorOutboundOptions{Options: map[string]string{"SocksPort": "9050"}}, "torrc.SocksPort"},
		{option.TorOutboundOptions{Options: map[string]string{"ControlPort": "9051"}}, "torrc.ControlPort"},
		{option.TorOutboundOptions{Options: map[string]string{"HiddenServiceDir": "identity"}}, "torrc.HiddenServiceDir"},
		{option.TorOutboundOptions{Options: map[string]string{"socks5proxy": "other"}}, "torrc.socks5proxy"},
	}
	for _, test := range cases {
		field, reason := RuntimeOverlapProblem(test.options)
		if field != test.field || reason == "" {
			t.Fatalf("got %q %q, want %q", field, reason, test.field)
		}
	}
}

func TestRuntimeTorOverlapDeterministicAndDoesNotMutate(t *testing.T) {
	options := option.TorOutboundOptions{Options: map[string]string{"SocksPort": "9050", "ControlPort": "9051"}}
	for i := 0; i < 10; i++ {
		field, _ := RuntimeOverlapProblem(options)
		if field != "torrc.ControlPort" {
			t.Fatal(field)
		}
	}
	if len(options.Options) != 2 || options.Options["SocksPort"] != "9050" {
		t.Fatal("classifier mutated options")
	}
}
