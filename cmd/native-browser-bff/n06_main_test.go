package main

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/assurance"
)

// Protect the exact, owner-reviewed authentication-only scope mapping.
// Adding OAuth scopes must not silently change native assurance semantics.
func TestN06NativeExecutableRejectsUnreviewedScope(t *testing.T) {
	allowed, err := n06NativeScopePolicy("openid trade:buy")
	if err != nil || len(allowed) != 1 || allowed["trade:buy"] != assurance.OrdinaryBuyer {
		t.Fatal("the reviewed browser scope requires an explicit assurance operation")
	}
	for _, scope := range []string{
		"", "openid", "trade:buy", "openid  trade:buy", "openid trade:buy ",
		"openid trade:buy profile", "openid identity:admin", "openid trade:buy trade:buy",
	} {
		if _, err := n06NativeScopePolicy(scope); err == nil {
			t.Fatalf("unreviewed scope %q unexpectedly accepted", scope)
		}
	}
}

// An unqualified independent risk source must never be replaced by a
// fabricated low-risk or privileged context, even if Kratos is reachable.
func TestN06NativeExecutableRefusesInventedCurrentRisk(t *testing.T) {
	risk, err := (unavailableN06Risk{}).CurrentRisk(
		context.Background(), assurance.CurrentSessionKey{Issuer: "synthetic"},
		assurance.CommitBuyer,
	)
	if err == nil || !risk.ObservedAt.IsZero() || risk.PrivilegedContextVerified {
		t.Fatal("unavailable current risk witness must not become an approval")
	}
}

// Regression against the original executable bug: testing an N06-enabled
// library handler is insufficient if the real command constructs that handler
// without N06Required, scope policy and current security gate.
func TestN06ActualNativeExecutableCannotOmitGate(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	matched := 0
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "New" {
			return true
		}
		owner, ok := sel.X.(*ast.Ident)
		if !ok || owner.Name != "nativebff" {
			return true
		}
		config, ok := call.Args[0].(*ast.CompositeLit)
		if !ok {
			t.Fatal("native BFF must use a statically reviewed configuration")
		}
		typ, ok := config.Type.(*ast.SelectorExpr)
		if !ok || typ.Sel.Name != "Config" {
			t.Fatal("native BFF must use the governed config type")
		}
		fields := map[string]string{}
		for _, raw := range config.Elts {
			field, ok := raw.(*ast.KeyValueExpr)
			if !ok {
				t.Fatal("unkeyed native BFF config bypasses reviewed gate")
			}
			name, ok := field.Key.(*ast.Ident)
			if !ok {
				t.Fatal("unreviewed native BFF config selector")
			}
			val, ok := field.Value.(*ast.Ident)
			if ok {
				fields[name.Name] = val.Name
			}
		}
		if fields["N06Required"] != "true" ||
			fields["N06ScopeOperations"] != "scopePolicy" ||
			fields["N06Gate"] != "n06Gate" {
			t.Fatal("executable native BFF must enable the current N06 assurance gate")
		}
		matched++
		return true
	})
	if matched != 1 {
		t.Fatalf("expected one guarded native BFF executable constructor, got %d", matched)
	}
}
