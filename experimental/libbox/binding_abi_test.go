package libbox

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"regexp"
	"strings"
	"testing"

	"github.com/sagernet/gomobile/bind"
)

// TestBindingAcronymSetters checks generated selectors against the actual API
// declarations, including the bridge into the Go field. It does not execute an
// Apple binary or replace a native Swift -> ObjC -> Go value round trip.
func TestBindingAcronymSetters(t *testing.T) {
	selected := map[string]bool{
		"NetworkInterface": true, "BridgeOptions": true, "WIFIState": true,
		"Notification": true, "StringIterator": true,
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, name := range []string{"platform.go", "iterator.go"} {
		file, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		// Project these complete type declarations without unrelated platform
		// services/imports. Do not hand-copy the fields under test into fixtures.
		var declarations []ast.Decl
		for _, declaration := range file.Decls {
			group, ok := declaration.(*ast.GenDecl)
			if !ok || group.Tok != token.TYPE {
				continue
			}
			var specs []ast.Spec
			for _, spec := range group.Specs {
				if selected[spec.(*ast.TypeSpec).Name.Name] {
					specs = append(specs, spec)
				}
			}
			if len(specs) != 0 {
				copy := *group
				copy.Specs = specs
				declarations = append(declarations, &copy)
			}
		}
		file.Decls, file.Imports = declarations, nil
		files = append(files, file)
	}
	pkg, err := (&types.Config{}).Check("github.com/sagernet/sing-box/experimental/libbox", fset, files, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name := range selected {
		if pkg.Scope().Lookup(name) == nil {
			t.Fatalf("missing source declaration %s", name)
		}
	}
	generateObjC := func(header bool) string {
		t.Helper()
		var output bytes.Buffer
		generator := &bind.ObjcGen{Generator: &bind.Generator{
			Printer: &bind.Printer{Buf: &output, IndentEach: []byte("\t")},
			Fset:    fset, Files: files, Pkg: pkg, AllPkg: []*types.Package{pkg},
		}}
		generator.Init(nil)
		var err error
		if header {
			err = generator.GenH()
		} else {
			err = generator.GenM()
		}
		if err != nil {
			t.Fatal(err)
		}
		return output.String()
	}
	header, implementation := generateObjC(true), generateObjC(false)
	var goOutput bytes.Buffer
	if err := bind.GenGo(&bind.GeneratorConfig{Writer: &goOutput, Fset: fset, Pkg: pkg, AllPkg: []*types.Package{pkg}}); err != nil {
		t.Fatal(err)
	}
	for _, field := range []struct{ owner, name, property string }{
		{"NetworkInterface", "MTU", "mtu"},
		{"NetworkInterface", "DNSServer", "dnsServer"},
		{"NetworkInterface", "DNSSearchDomain", "dnsSearchDomain"},
		{"BridgeOptions", "MTU", "mtu"},
		{"WIFIState", "SSID", "ssid"},
		{"WIFIState", "BSSID", "bssid"},
		{"Notification", "OpenURL", "openURL"},
	} {
		t.Run(field.owner+"."+field.name, func(t *testing.T) {
			class := regexp.QuoteMeta("Libbox" + field.owner)
			declaration := regexp.MustCompile(`(?s)@interface ` + class + `\b.*?@end`).FindString(header)
			property := `@property \(nonatomic, setter=set` + field.name + `:\) [^;]+ ` + field.property + `;`
			if !regexp.MustCompile(property).MatchString(declaration) {
				t.Fatalf("property must select implemented set%s: for %s", field.name, field.property)
			}
			body := regexp.MustCompile(`(?s)@implementation ` + class + `\b.*?@end`).FindString(implementation)
			setter := regexp.MustCompile(`(?s)- \(void\)set` + field.name + `:\([^)]*\)v \{.*?\n\}`).FindString(body)
			proxy := "proxylibbox_" + field.owner + "_" + field.name
			if !strings.Contains(setter, proxy+"_Set(refnum, _v);") {
				t.Fatal("ObjC setter does not call the matching Go export")
			}
			for _, expected := range []string{
				"//export " + proxy + "_Set", "//export " + proxy + "_Get",
				"ref.Get().(*libbox." + field.owner + ")." + field.name + " = _v",
				"v := ref.Get().(*libbox." + field.owner + ")." + field.name,
			} {
				if !strings.Contains(goOutput.String(), expected) {
					t.Fatalf("generated Go bridge missing %q", expected)
				}
			}
		})
	}
}
