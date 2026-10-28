package tor

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// This source-contract fixture checks the precise startup-rollback race fix.
// It does not start Tor, wait for native exit or assert the 300 ms observer is
// a completion guarantee. The integration owns those separate barriers.
func TestCloseCapturesProcessBeforeDispatch(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "tor.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	ast.Inspect(file, func(node ast.Node) bool {
		statement, ok := node.(*ast.GoStmt)
		if !ok {
			return true
		}
		literal, ok := statement.Call.Fun.(*ast.FuncLit)
		if !ok {
			return true
		}
		for _, item := range literal.Body.List {
			send, ok := item.(*ast.SendStmt)
			if !ok {
				continue
			}
			call, ok := send.Value.(*ast.CallExpr)
			if !ok {
				continue
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Wait" {
				continue
			}
			receiver, ok := selector.X.(*ast.Ident)
			if !ok || receiver.Name != "owned" {
				t.Fatal("worker rereads mutable Tor.Process")
			}
			if len(statement.Call.Args) != 1 || len(literal.Type.Params.List) != 1 {
				t.Fatal("process not captured at dispatch")
			}
			argument, ok := statement.Call.Args[0].(*ast.SelectorExpr)
			if !ok || argument.Sel.Name != "Process" {
				t.Fatal("wrong captured process")
			}
			found = true
		}
		return true
	})
	if !found {
		t.Fatal("process wait dispatch not found")
	}
}
