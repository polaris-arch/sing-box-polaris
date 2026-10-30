//go:build with_purego && windows

package cronet

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// The loader tests never call LoadLibraryEx or bind real module addresses.
// Every case owns its loader and dependencies; process loader state is untouched.
type windowsLoaderCall struct {
	path  string
	flags uintptr
}

type windowsLoaderProbe struct {
	selector    string
	present     bool
	discovery   string
	discoveries int
	loads       []windowsLoaderCall
	registered  []uintptr
	freed       []uintptr
	handle      uintptr
	loadErr     error
	registerErr error
	freeErr     error
}

func (probe *windowsLoaderProbe) ops() windowsLibraryOps {
	return windowsLibraryOps{
		lookupEnv: func(key string) (string, bool) {
			if key != cronetLibraryPathEnv {
				panic("unexpected environment lookup")
			}
			return probe.selector, probe.present
		},
		discover: func() string {
			probe.discoveries++
			return probe.discovery
		},
		load: func(path string, flags uintptr) (uintptr, error) {
			probe.loads = append(probe.loads, windowsLoaderCall{path, flags})
			return probe.handle, probe.loadErr
		},
		free: func(handle uintptr) error {
			probe.freed = append(probe.freed, handle)
			return probe.freeErr
		},
		register: func(handle uintptr) error {
			probe.registered = append(probe.registered, handle)
			return probe.registerErr
		},
	}
}

func windowsLibraryFixture(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("unit-test placeholder, never loaded"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWindowsExplicitLibrarySelector(t *testing.T) {
	selected := windowsLibraryFixture(t, "trusted library.dll")
	other := windowsLibraryFixture(t, "other.dll")
	missing := filepath.Join(t.TempDir(), "missing.dll")
	directory := t.TempDir()
	// Both spellings exist: only the extensionless selector is admitted to the
	// test, and native loading must not get an opportunity to choose its decoy.
	extensionless := windowsLibraryFixture(t, "cronet")
	if err := os.WriteFile(extensionless+".dll", []byte("decoy, never loaded"), 0600); err != nil {
		t.Fatal(err)
	}
	withoutDecoy := windowsLibraryFixture(t, "no-decoy")
	dottedDirectory := filepath.Join(t.TempDir(), "parent.with.dots")
	if err := os.Mkdir(dottedDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	dottedParentFile := filepath.Join(dottedDirectory, "cronet")
	for _, path := range []string{dottedParentFile, dottedParentFile + ".dll"} {
		if err := os.WriteFile(path, []byte("placeholder, never loaded"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name      string
		selector  string
		request   string
		wantError bool
	}{
		{name: "absolute selected DLL", selector: selected},
		{name: "matching argument", selector: selected, request: selected},
		{name: "matching clean argument", selector: selected, request: filepath.Dir(selected) + `\unused\..\` + filepath.Base(selected)},
		{name: "provided empty", selector: "", wantError: true},
		{name: "provided empty with argument", selector: "", request: selected, wantError: true},
		{name: "missing selected file", selector: missing, wantError: true},
		{name: "relative selected file", selector: "libcronet.dll", wantError: true},
		{name: "drive relative selected file", selector: `C:libcronet.dll`, wantError: true},
		{name: "root relative selected file", selector: `\libcronet.dll`, wantError: true},
		{name: "NUL selected file", selector: selected + "\x00.dll", wantError: true},
		{name: "selected directory", selector: directory, wantError: true},
		{name: "extensionless existing selector with DLL decoy", selector: extensionless, wantError: true},
		{name: "extensionless matching argument with DLL decoy", selector: extensionless, request: extensionless, wantError: true},
		{name: "extensionless existing selector without decoy", selector: withoutDecoy, wantError: true},
		{name: "extensionless basename in dotted directory", selector: dottedParentFile, wantError: true},
		{name: "extensionless argument with valid selector", selector: selected, request: extensionless, wantError: true},
		{name: "conflicting argument", selector: selected, request: other, wantError: true},
		{name: "relative argument with selector", selector: selected, request: filepath.Base(selected), wantError: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var loader windowsLibraryLoader
			probe := windowsLoaderProbe{selector: tc.selector, present: true, discovery: other, handle: 71}
			err := loader.load(tc.request, probe.ops())
			if (err != nil) != tc.wantError {
				t.Fatalf("load error = %v, wantError = %v", err, tc.wantError)
			}
			if probe.discoveries != 0 {
				t.Fatal("explicit selector reached executable/PATH discovery")
			}
			if tc.wantError {
				if len(probe.loads) != 0 || loader.handle != 0 || len(probe.registered) != 0 {
					t.Fatalf("invalid selection reached native loading: %+v", probe)
				}
				return
			}
			if len(probe.loads) != 1 || probe.loads[0].path != selected || probe.loads[0].flags != 0x900 {
				t.Fatalf("load did not use exact selected path and DLL-directory/System32 flags: %+v", probe.loads)
			}
			if loader.handle != 71 || !loader.explicit || len(probe.freed) != 0 {
				t.Fatalf("successful module was not retained: loader=%+v, freed=%v", &loader, probe.freed)
			}
		})
	}
}

func TestWindowsExplicitLibraryNeverFallsBackAfterLoadFailure(t *testing.T) {
	selected := windowsLibraryFixture(t, "selected.dll")
	decoy := windowsLibraryFixture(t, "PATH-or-CWD-decoy.dll")
	failure := errors.New("selected image cannot be loaded")
	var loader windowsLibraryLoader
	probe := windowsLoaderProbe{selector: selected, present: true, discovery: decoy, loadErr: failure}
	for i := 0; i < 2; i++ {
		if err := loader.load("", probe.ops()); !errors.Is(err, failure) {
			t.Fatalf("load error = %v, want selected image failure", err)
		}
	}
	if probe.discoveries != 0 || len(probe.loads) != 1 || probe.loads[0].path != selected || len(probe.registered) != 0 {
		t.Fatalf("failure retried or used a fallback: %+v", probe)
	}
}

func TestWindowsStandaloneLibraryDiscovery(t *testing.T) {
	selected := windowsLibraryFixture(t, "standalone.dll")
	t.Run("absent selector uses compatibility discovery once", func(t *testing.T) {
		var loader windowsLibraryLoader
		probe := windowsLoaderProbe{discovery: selected, handle: 71}
		for i := 0; i < 2; i++ {
			if err := loader.load("", probe.ops()); err != nil {
				t.Fatal(err)
			}
		}
		if probe.discoveries != 1 || len(probe.loads) != 1 || loader.explicit || probe.loads[0].path != selected || probe.loads[0].flags != 0x900 {
			t.Fatalf("standalone discovery = %+v", probe)
		}
	})
	t.Run("explicit caller path skips compatibility discovery", func(t *testing.T) {
		var loader windowsLibraryLoader
		probe := windowsLoaderProbe{handle: 71}
		if err := loader.load(selected, probe.ops()); err != nil {
			t.Fatal(err)
		}
		if probe.discoveries != 0 || len(probe.loads) != 1 || probe.loads[0].path != selected {
			t.Fatalf("caller path = %+v", probe)
		}
	})
	t.Run("standalone relative caller becomes absolute before loading", func(t *testing.T) {
		t.Chdir(filepath.Dir(selected))
		var loader windowsLibraryLoader
		probe := windowsLoaderProbe{handle: 71}
		if err := loader.load(filepath.Base(selected), probe.ops()); err != nil {
			t.Fatal(err)
		}
		if len(probe.loads) != 1 || probe.loads[0].path != selected || probe.loads[0].flags != 0x900 {
			t.Fatalf("relative caller = %+v", probe.loads)
		}
	})
	t.Run("absent selector preserves standalone extensionless caller", func(t *testing.T) {
		extensionless := windowsLibraryFixture(t, "standalone")
		var loader windowsLibraryLoader
		probe := windowsLoaderProbe{handle: 71}
		if err := loader.load(extensionless, probe.ops()); err != nil {
			t.Fatal(err)
		}
		if probe.discoveries != 0 || len(probe.loads) != 1 || probe.loads[0].path != extensionless || probe.loads[0].flags != 0x900 || loader.explicit {
			t.Fatalf("standalone extensionless compatibility = %+v", probe)
		}
	})
	t.Run("absent selector preserves standalone extensionless discovery", func(t *testing.T) {
		extensionless := windowsLibraryFixture(t, "standalone")
		var loader windowsLibraryLoader
		probe := windowsLoaderProbe{handle: 71, discovery: extensionless}
		if err := loader.load("", probe.ops()); err != nil {
			t.Fatal(err)
		}
		if probe.discoveries != 1 || len(probe.loads) != 1 || probe.loads[0].path != extensionless || loader.explicit {
			t.Fatalf("standalone extensionless discovery = %+v", probe)
		}
	})
	t.Run("missing standalone discovery fails without loading", func(t *testing.T) {
		var loader windowsLibraryLoader
		probe := windowsLoaderProbe{handle: 71}
		if err := loader.load("", probe.ops()); err == nil {
			t.Fatal("missing discovery accepted")
		}
		if probe.discoveries != 1 || len(probe.loads) != 0 {
			t.Fatalf("missing discovery = %+v", probe)
		}
	})
}

func TestWindowsLibrarySelectionCannotChangeAfterLoad(t *testing.T) {
	selected := windowsLibraryFixture(t, "selected.dll")
	other := windowsLibraryFixture(t, "other.dll")
	cases := []struct {
		name    string
		change  func(*windowsLoaderProbe)
		request string
	}{
		{name: "different selector", change: func(p *windowsLoaderProbe) { p.selector = other }},
		{name: "removed selector", change: func(p *windowsLoaderProbe) { p.present = false }},
		{name: "empty selector", change: func(p *windowsLoaderProbe) { p.selector = "" }},
		{name: "relative selector", change: func(p *windowsLoaderProbe) { p.selector = "libcronet.dll" }},
		{name: "extensionless repeated selector", change: func(p *windowsLoaderProbe) { p.selector = strings.TrimSuffix(selected, ".dll") }},
		{name: "extensionless repeated argument", change: func(*windowsLoaderProbe) {}, request: strings.TrimSuffix(selected, ".dll")},
		{name: "conflicting repeated argument", change: func(*windowsLoaderProbe) {}, request: other},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var loader windowsLibraryLoader
			probe := windowsLoaderProbe{selector: selected, present: true, handle: 71}
			if err := loader.load("", probe.ops()); err != nil {
				t.Fatal(err)
			}
			tc.change(&probe)
			if err := loader.load(tc.request, probe.ops()); err == nil {
				t.Fatal("changed selection accepted")
			}
			if len(probe.loads) != 1 || loader.handle != 71 || len(probe.freed) != 0 || probe.discoveries != 0 {
				t.Fatalf("changed selection altered module lifetime: %+v", probe)
			}
		})
	}
	t.Run("adding selector to standalone module is rejected", func(t *testing.T) {
		var loader windowsLibraryLoader
		probe := windowsLoaderProbe{discovery: selected, handle: 71}
		if err := loader.load("", probe.ops()); err != nil {
			t.Fatal(err)
		}
		probe.selector, probe.present = selected, true
		if err := loader.load("", probe.ops()); err == nil || len(probe.loads) != 1 {
			t.Fatalf("late selector accepted: %v, %+v", err, probe)
		}
	})
}

func TestWindowsLibraryWarmCallDoesNotRestat(t *testing.T) {
	selected := windowsLibraryFixture(t, "selected.dll")
	var loader windowsLibraryLoader
	probe := windowsLoaderProbe{selector: selected, present: true, handle: 71}
	if err := loader.load("", probe.ops()); err != nil {
		t.Fatal(err)
	}
	// This fixture is a placeholder, not an actual mapped module or user file.
	if err := os.Remove(selected); err != nil {
		t.Fatal(err)
	}
	if err := loader.load("", probe.ops()); err != nil {
		t.Fatalf("warm call rechecked the pathname instead of retaining the module: %v", err)
	}
	if len(probe.loads) != 1 || len(probe.freed) != 0 {
		t.Fatalf("warm module lifetime = %+v", probe)
	}
}

func TestWindowsLibraryInitialSelectionFailureIsSticky(t *testing.T) {
	selected := windowsLibraryFixture(t, "valid.dll")
	var loader windowsLibraryLoader
	probe := windowsLoaderProbe{present: true, handle: 71}
	first := loader.load("", probe.ops())
	if first == nil {
		t.Fatal("empty explicit selector accepted")
	}
	probe.selector = selected
	if next := loader.load("", probe.ops()); next != first {
		t.Fatalf("first initialization failure was not retained: first=%v next=%v", first, next)
	}
	if len(probe.loads) != 0 || probe.discoveries != 0 {
		t.Fatalf("sticky selection failure retried: %+v", probe)
	}
}

func TestWindowsLibraryHandleLifetime(t *testing.T) {
	selected := windowsLibraryFixture(t, "selected.dll")
	loadFailure := errors.New("native load failed")
	registrationFailure := errors.New("required export missing")
	releaseFailure := errors.New("native release failed")
	cases := []struct {
		name            string
		handle          uintptr
		loadErr         error
		registrationErr error
		freeErr         error
		wantError       error
		wantFree        int
		wantRegister    int
	}{
		{name: "load failure", loadErr: loadFailure, wantError: loadFailure},
		{name: "load failure carrying handle", handle: 71, loadErr: loadFailure, wantError: loadFailure, wantFree: 1},
		{name: "registration failure", handle: 71, registrationErr: registrationFailure, wantError: registrationFailure, wantFree: 1, wantRegister: 1},
		{name: "release error preserved", handle: 71, registrationErr: registrationFailure, freeErr: releaseFailure, wantError: releaseFailure, wantFree: 1, wantRegister: 1},
		{name: "successful module pinned", handle: 71, wantRegister: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var loader windowsLibraryLoader
			probe := windowsLoaderProbe{selector: selected, present: true, handle: tc.handle, loadErr: tc.loadErr, registerErr: tc.registrationErr, freeErr: tc.freeErr}
			for i := 0; i < 2; i++ {
				err := loader.load("", probe.ops())
				if !errors.Is(err, tc.wantError) {
					t.Fatalf("error = %v, want %v", err, tc.wantError)
				}
				if tc.freeErr != nil && !errors.Is(err, registrationFailure) {
					t.Fatalf("release error erased registration failure: %v", err)
				}
			}
			if len(probe.loads) != 1 || len(probe.freed) != tc.wantFree || len(probe.registered) != tc.wantRegister {
				t.Fatalf("module operations = %+v", probe)
			}
			if tc.wantError != nil && loader.handle != 0 {
				t.Fatal("failed module published")
			}
			if tc.wantError == nil && loader.handle != tc.handle {
				t.Fatal("successful module not retained")
			}
		})
	}
	t.Run("empty native handle is rejected", func(t *testing.T) {
		var loader windowsLibraryLoader
		probe := windowsLoaderProbe{selector: selected, present: true}
		if err := loader.load("", probe.ops()); err == nil {
			t.Fatal("zero native handle accepted")
		}
		if len(probe.registered) != 0 || len(probe.freed) != 0 || loader.handle != 0 {
			t.Fatalf("zero handle operations = %+v", probe)
		}
	})
	t.Run("registration panic fails closed and releases handle", func(t *testing.T) {
		var loader windowsLibraryLoader
		probe := windowsLoaderProbe{selector: selected, present: true, handle: 71}
		ops := probe.ops()
		ops.register = func(uintptr) error { panic("registration panic") }
		if err := loader.load("", ops); err == nil || !strings.Contains(err.Error(), "registration panic") {
			t.Fatalf("panic result = %v", err)
		}
		if loader.handle != 0 || len(probe.freed) != 1 {
			t.Fatalf("panic lifetime = %+v", probe)
		}
	})
	t.Run("module is unpublished until registration completes", func(t *testing.T) {
		var loader windowsLibraryLoader
		probe := windowsLoaderProbe{selector: selected, present: true, handle: 71}
		ops := probe.ops()
		ops.register = func(handle uintptr) error {
			if loader.handle != 0 || handle != 71 {
				t.Fatal("partially registered module was published")
			}
			return nil
		}
		if err := loader.load("", ops); err != nil || loader.handle != 71 {
			t.Fatalf("publication result = %v", err)
		}
	})
}

func TestWindowsLibraryConcurrentLoadOnce(t *testing.T) {
	selected := windowsLibraryFixture(t, "selected.dll")
	var loader windowsLibraryLoader
	probe := windowsLoaderProbe{selector: selected, present: true, handle: 71}
	ops := probe.ops()
	var workers sync.WaitGroup
	results := make(chan error, 16)
	for i := 0; i < cap(results); i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			results <- loader.load("", ops)
		}()
	}
	workers.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(probe.loads) != 1 || len(probe.registered) != 1 || len(probe.freed) != 0 {
		t.Fatalf("concurrent initialization = %+v", probe)
	}
}

func TestWindowsLibrarySymbolPreflight(t *testing.T) {
	cases := []struct {
		name        string
		handle      uintptr
		target      interface{}
		failLookup  bool
		zeroAddress bool
	}{
		{name: "missing export", handle: 71, failLookup: true},
		{name: "empty export address", handle: 71, zeroAddress: true},
		{name: "empty module handle"},
		{name: "invalid function target", handle: 71, target: new(int)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var first, second func() int
			secondTarget := tc.target
			if secondTarget == nil {
				secondTarget = &second
			}
			symbols := []windowsLibrarySymbol{{"first", &first}, {"second", secondTarget}}
			binds := 0
			lookup := func(handle uintptr, name string) (uintptr, error) {
				if handle != 71 {
					t.Fatalf("wrong lookup handle: %v", handle)
				}
				if name == "second" && tc.failLookup {
					return 0, errors.New("missing export")
				}
				if name == "second" && tc.zeroAddress {
					return 0, nil
				}
				return 100, nil
			}
			err := bindWindowsLibrarySymbols(tc.handle, symbols, lookup, func(interface{}, uintptr) { binds++ })
			if err == nil || binds != 0 || first != nil || second != nil {
				t.Fatalf("preflight published a partial binding: err=%v binds=%d", err, binds)
			}
		})
	}
}

func TestWindowsLibrarySymbolBindingRollback(t *testing.T) {
	first := func() int { return 1 }
	second := func() int { return 2 }
	symbols := []windowsLibrarySymbol{{"first", &first}, {"second", &second}}
	lookups, bindings := 0, 0
	lookup := func(handle uintptr, name string) (uintptr, error) {
		if handle != 71 {
			t.Fatal("wrong module handle")
		}
		lookups++
		return uintptr(lookups), nil
	}
	bind := func(target interface{}, address uintptr) {
		if lookups != len(symbols) {
			t.Fatal("binding started before all exports were resolved")
		}
		bindings++
		reflect.ValueOf(target).Elem().Set(reflect.ValueOf(func() int { return int(address) + 100 }))
		if bindings == 2 {
			panic("reject second binding")
		}
	}
	err := bindWindowsLibrarySymbols(71, symbols, lookup, bind)
	if err == nil || !strings.Contains(err.Error(), "reject second binding") || first() != 1 || second() != 2 || bindings != 2 {
		t.Fatalf("rollback incomplete: err=%v first=%d second=%d bindings=%d", err, first(), second(), bindings)
	}
}

func TestWindowsLibrarySymbolBindingSuccess(t *testing.T) {
	var first, second func() int
	symbols := []windowsLibrarySymbol{{"first", &first}, {"second", &second}}
	lookup := func(handle uintptr, name string) (uintptr, error) {
		if handle != 71 {
			t.Fatal("wrong module handle")
		}
		if name == "first" {
			return 101, nil
		}
		return 202, nil
	}
	bind := func(target interface{}, address uintptr) {
		reflect.ValueOf(target).Elem().Set(reflect.ValueOf(func() int { return int(address) }))
	}
	if err := bindWindowsLibrarySymbols(71, symbols, lookup, bind); err != nil {
		t.Fatal(err)
	}
	if first() != 101 || second() != 202 {
		t.Fatalf("bindings reference wrong exports: %d %d", first(), second())
	}
}

func TestWindowsLibraryProductionSymbolRegistry(t *testing.T) {
	symbols := windowsLibrarySymbols()
	if len(symbols) != 255 {
		t.Fatalf("symbol registry changed: got %d, want original253 plus two floating-point exports", len(symbols))
	}
	names := make(map[string]bool)
	targets := make(map[uintptr]bool)
	for _, symbol := range symbols {
		target := reflect.ValueOf(symbol.target)
		if symbol.name == "" || names[symbol.name] || target.Kind() != reflect.Ptr || target.IsNil() || target.Elem().Kind() != reflect.Func || targets[target.Pointer()] {
			t.Fatalf("invalid or duplicated registry entry: %s", symbol.name)
		}
		names[symbol.name] = true
		targets[target.Pointer()] = true
	}
	for _, name := range []string{"Cronet_EngineParams_network_thread_priority_set", "Cronet_EngineParams_network_thread_priority_get"} {
		if !names[name] {
			t.Fatalf("missing architecture floating-point export: %s", name)
		}
	}
}
