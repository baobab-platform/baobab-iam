package federation

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileAuthorityTokensRotateAndFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service-token")
	s := FileAuthorityTokens{path}
	if _, err := s.Token(context.Background()); err == nil {
		t.Fatal("missing accepted")
	}
	if err := os.WriteFile(path, []byte("first-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if token, err := s.Token(context.Background()); err != nil || token != "first-token" {
		t.Fatal(token, err)
	}
	if err := os.WriteFile(path, []byte("rotated-token"), 0600); err != nil {
		t.Fatal(err)
	}
	if token, err := s.Token(context.Background()); err != nil || token != "rotated-token" {
		t.Fatal(token, err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Token(context.Background()); err == nil {
		t.Fatal("public token accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", " padded ", "two\ntokens", "token\r\n", strings.Repeat("a", 16385)} {
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Token(context.Background()); err == nil {
			t.Fatal("bad token accepted")
		}
	}
	link := filepath.Join(t.TempDir(), "symlink")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileAuthorityTokens{link}).Token(context.Background()); err == nil {
		t.Fatal("symlink token accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Token(ctx); err == nil {
		t.Fatal("cancelled accepted")
	}
}
