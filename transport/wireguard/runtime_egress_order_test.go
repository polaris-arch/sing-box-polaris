package wireguard

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"testing"
)

// This structural regression protects terminal ordering even on platforms
// without native sockets. It is not a replacement for native race coverage.
func TestRuntimeEgressTerminalCloseFollowsOriginalWorkerJoins(t *testing.T) {
	source, err := os.ReadFile("endpoint.go")
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "endpoint.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	var body *ast.BlockStmt
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Recv != nil && function.Name.Name == "close" {
			body = function.Body
		}
	}
	if body == nil {
		t.Fatal("endpoint close implementation missing")
	}
	var nativeClose, runtimeWait, poolClose token.Pos
	ast.Inspect(body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if receiver, ok := selector.X.(*ast.Ident); ok && receiver.Name == "wgDevice" && selector.Sel.Name == "Close" {
			nativeClose = call.Pos()
		}
		field, ok := selector.X.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if field.Sel.Name == "runtime" && selector.Sel.Name == "wait" {
			runtimeWait = call.Pos()
		}
		if field.Sel.Name == "egressPool" && selector.Sel.Name == "Close" {
			if poolClose != token.NoPos {
				t.Fatal("multiple terminal pool closes")
			}
			poolClose = call.Pos()
		}
		return true
	})
	if nativeClose == token.NoPos || runtimeWait == token.NoPos || poolClose == token.NoPos || poolClose < nativeClose || poolClose < runtimeWait {
		t.Fatal("egress pool must close after original native and pause worker joins")
	}
}
