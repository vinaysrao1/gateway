package security

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// NET-001/DST-002 structural tripwire complements real kernel boundary tests.
func TestExternalDialOwnership(t *testing.T) {
	root := filepath.Join("..", "..", "internal")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, e := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if e != nil {
			return e
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if kv, ok := n.(*ast.KeyValueExpr); ok {
				if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "InsecureSkipVerify" {
					t.Errorf("TLS verification bypass in %s", path)
				}
			}
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if strings.Contains(path, string(filepath.Separator)+"transport"+string(filepath.Separator)) {
				return true
			}
			if id.Name == "http" && (sel.Sel.Name == "DefaultClient" || sel.Sel.Name == "DefaultTransport" || sel.Sel.Name == "Get" || sel.Sel.Name == "Post") {
				t.Errorf("uncontrolled outbound HTTP in %s", path)
			}
			if id.Name == "net" && (sel.Sel.Name == "Dial" || sel.Sel.Name == "DialTimeout" || strings.HasPrefix(sel.Sel.Name, "Lookup")) {
				t.Errorf("external dialing outside transport in %s", path)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
