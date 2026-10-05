package federation

import (
	"context"
	"strings"
)

type governanceSubjectTokenKey struct{}

// WithGovernanceSubjectToken binds the independently authenticated human
// governance credential to this request context. It is request-local evidence:
// it is never persisted into approval/trust ledgers and must never be logged.
func WithGovernanceSubjectToken(ctx context.Context, token string) (context.Context, error) {
	if ctx == nil || token == "" || len(token) > 16384 || strings.ContainsAny(token, " \t\r\n") {
		return nil, ErrInvalid
	}
	return context.WithValue(ctx, governanceSubjectTokenKey{}, token), nil
}

func governanceSubjectToken(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	token, ok := ctx.Value(governanceSubjectTokenKey{}).(string)
	return token, ok && token != ""
}
