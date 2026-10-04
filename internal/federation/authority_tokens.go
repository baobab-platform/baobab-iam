package federation

import (
	"context"
	"io"
	"os"
	"strings"
)

// FileAuthorityTokens reads a rotated service-token file on EVERY request.
// Deployments own the credential acquisition/refresh process and protected
// parent directory. It accepts a private regular file only, never a symlink,
// environment token, URL, argv credential or cached stale value.
type FileAuthorityTokens struct{ Path string }

func (s FileAuthorityTokens) Token(ctx context.Context) (string, error) {
	if ctx == nil || ctx.Err() != nil || s.Path == "" {
		return "", ErrUnavailable
	}
	before, err := os.Lstat(s.Path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 {
		return "", ErrUnavailable
	}
	f, err := os.Open(s.Path)
	if err != nil {
		return "", ErrUnavailable
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || after.Mode().Perm()&0077 != 0 || !os.SameFile(before, after) {
		return "", ErrUnavailable
	}
	b, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || ctx.Err() != nil || len(b) > 16384 {
		return "", ErrUnavailable
	}
	// A single terminal newline is accepted for file-based token rotation;
	// padded/multiline credentials are rejected rather than normalized.
	token := strings.TrimSuffix(string(b), "\n")
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", ErrUnavailable
	}
	return token, nil
}

var _ AuthorityTokens = FileAuthorityTokens{}
