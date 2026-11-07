package libbox

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"github.com/sagernet/gomobile/bind"
)

// Generate the native ABI from the actual exported source declarations using
// the gomobile version already pinned in go.mod. Private implementation bodies
// are excluded; no source copy, SDK install or native compiler is required.
func TestRuntimeTunBindingUsesNullableInterfaceReturnAndExactSelectors(t *testing.T) {
	fset := token.NewFileSet()
	source, err := parser.ParseFile(fset, "runtime_tun.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	declarations := []ast.Decl{}
	for _, decl := range source.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			if d.Tok != token.TYPE {
				continue
			}
			for _, spec := range d.Specs {
				typ := spec.(*ast.TypeSpec)
				switch typ.Name.Name {
				case "RuntimeTunPlatform", "RuntimeTunSession":
					declarations = append(declarations, &ast.GenDecl{Tok: token.TYPE, Specs: []ast.Spec{typ}})
				case "RuntimeTunReceipt":
					declarations = append(declarations, &ast.GenDecl{Tok: token.TYPE, Specs: []ast.Spec{&ast.TypeSpec{Name: typ.Name, Type: &ast.StructType{Fields: &ast.FieldList{}}}}})
				}
			}
		case *ast.FuncDecl:
			if d.Recv == nil || len(d.Recv.List) != 1 {
				continue
			}
			receiver, ok := d.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			receiverName, ok := receiver.X.(*ast.Ident)
			if !ok {
				continue
			}
			keep := receiverName.Name == "RuntimeTunReceipt" && (d.Name.Name == "OwnerID" || d.Name.Name == "Published") || receiverName.Name == "CommandServer" && d.Name.Name == "SetRuntimeTunPlatform"
			if !keep {
				continue
			}
			copyMethod := *d
			copyMethod.Body = &ast.BlockStmt{List: []ast.Stmt{&ast.ExprStmt{X: &ast.CallExpr{Fun: ast.NewIdent("panic"), Args: []ast.Expr{&ast.BasicLit{Kind: token.STRING, Value: "\"ABI only\""}}}}}}
			declarations = append(declarations, &copyMethod)
		}
	}
	stubs, err := parser.ParseFile(fset, "abi_stubs.go", `package libbox; type TunOptions interface{}; type CommandServer struct{}`, 0)
	if err != nil {
		t.Fatal(err)
	}
	source.Decls = append(declarations, stubs.Decls...)
	source.Imports = nil
	conf := types.Config{}
	pkg, err := conf.Check("github.com/sagernet/sing-box/experimental/libbox", fset, []*ast.File{source}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var header bytes.Buffer
	gen := bind.ObjcGen{Generator: &bind.Generator{Printer: &bind.Printer{Buf: &header, IndentEach: []byte("  ")}, Fset: fset, Files: []*ast.File{source}, Pkg: pkg, AllPkg: []*types.Package{pkg}}}
	gen.Init(nil)
	if err = gen.GenH(); err != nil {
		t.Fatal(err)
	}
	for _, signature := range []string{
		"@protocol LibboxRuntimeTunPlatform <NSObject>",
		"@protocol LibboxRuntimeTunSession <NSObject>",
		"- (id<LibboxRuntimeTunSession> _Nullable)newTunSession:(id<LibboxTunOptions> _Nullable)options previous:(id<LibboxRuntimeTunSession> _Nullable)previous receipt:(LibboxRuntimeTunReceipt* _Nullable)receipt error:(NSError* _Nullable* _Nullable)error;",
		"- (BOOL)setRuntimeTunPlatform:(id<LibboxRuntimeTunPlatform> _Nullable)platform error:(NSError* _Nullable* _Nullable)error;",
		"- (NSString* _Nonnull)ownerID;",
		"- (BOOL)published;",
	} {
		if !strings.Contains(header.String(), signature) {
			t.Errorf("native ABI missing exact signature %q", signature)
		}
	}
	if strings.Contains(header.String(), "ret0_") {
		t.Fatal("nullable native session return unexpectedly became an output parameter")
	}
}
