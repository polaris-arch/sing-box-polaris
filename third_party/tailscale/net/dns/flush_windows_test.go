// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package dns

import (
	"errors"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

type fakeResolverCacheFlushProcedure struct {
	findErr error
	result  uintptr
	lastErr error
	events  []string
	args    []uintptr
}

func (p *fakeResolverCacheFlushProcedure) Find() error {
	p.events = append(p.events, "find")
	return p.findErr
}

func (p *fakeResolverCacheFlushProcedure) Call(args ...uintptr) (uintptr, uintptr, error) {
	p.events = append(p.events, "call")
	p.args = append(p.args, args...)
	return p.result, 99, p.lastErr
}

func TestWindowsResolverCacheFlush(t *testing.T) {
	// These tests are deliberately serial: every entry point uses this private
	// procedure seam, and no test resolves or calls the real Windows procedure.
	for _, entry := range []struct {
		name string
		call func() error
	}{
		{"private", flushCaches},
		{"public", Flush},
	} {
		t.Run(entry.name, func(t *testing.T) {
			for _, tt := range []struct {
				name    string
				findErr error
				result  uintptr
				lastErr error
				wantErr error
				wantMsg string
			}{
				{name: "true-zero-last-error", result: 1, lastErr: windows.ERROR_SUCCESS},
				{name: "true-stale-last-error", result: 1, lastErr: windows.ERROR_ACCESS_DENIED},
				{name: "true-nil-last-error", result: 1},
				{name: "true-noncanonical-bool", result: 2, lastErr: windows.ERROR_ACCESS_DENIED},
				{name: "true-negative-bool", result: 0x80000000, lastErr: windows.ERROR_ACCESS_DENIED},
				{name: "false-last-error", lastErr: windows.ERROR_ACCESS_DENIED, wantErr: windows.ERROR_ACCESS_DENIED},
				{name: "false-zero-last-error", lastErr: windows.ERROR_SUCCESS, wantMsg: "returned FALSE without a last error"},
				{name: "false-nil-last-error", wantMsg: "returned FALSE without a last error"},
				{name: "missing-dll", findErr: windows.ERROR_MOD_NOT_FOUND, wantErr: windows.ERROR_MOD_NOT_FOUND},
				{name: "missing-procedure", findErr: windows.ERROR_PROC_NOT_FOUND, wantErr: windows.ERROR_PROC_NOT_FOUND},
			} {
				t.Run(tt.name, func(t *testing.T) {
					fake := &fakeResolverCacheFlushProcedure{findErr: tt.findErr, result: tt.result, lastErr: tt.lastErr}
					original := resolverCacheFlush
					resolverCacheFlush = fake
					t.Cleanup(func() { resolverCacheFlush = original })
					err := entry.call()
					if tt.wantErr != nil {
						if !errors.Is(err, tt.wantErr) {
							t.Fatalf("error = %v, want wrapped %v", err, tt.wantErr)
						}
					} else if tt.wantMsg != "" {
						if err == nil || !strings.Contains(err.Error(), tt.wantMsg) {
							t.Fatalf("error = %v, want %q", err, tt.wantMsg)
						}
					} else if err != nil {
						t.Fatalf("successful BOOL returned error: %v", err)
					}
					wantEvents := []string{"find", "call"}
					if tt.findErr != nil {
						wantEvents = []string{"find"}
					}
					if !reflect.DeepEqual(fake.events, wantEvents) {
						t.Fatalf("native sequence = %v, want %v", fake.events, wantEvents)
					}
					if len(fake.args) != 0 {
						t.Fatalf("native call received arguments: %v", fake.args)
					}
				})
			}
		})
	}
}

func TestWindowsResolverCacheFlushUsesSystemDLL(t *testing.T) {
	// Inspecting the lazy binding must not call Find, Addr, Load, or Call.
	proc, ok := resolverCacheFlush.(*windows.LazyProc)
	if !ok || proc.Name != "DnsFlushResolverCache" {
		t.Fatalf("native procedure = %T, want DnsFlushResolverCache LazyProc", resolverCacheFlush)
	}
	if resolverCacheDLL.Name != "dnsapi.dll" || !resolverCacheDLL.System {
		t.Fatalf("native DLL = %+v, want System32 dnsapi.dll", resolverCacheDLL)
	}
	source, err := os.ReadFile("flush_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "flush_windows.go", source, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range file.Imports {
		name, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		if name != "fmt" && name != "golang.org/x/sys/windows" {
			t.Fatalf("cache flush imported unexpected package %q", name)
		}
	}
}
