// Target path: baobab-iam/internal/provider/errors.go
//
// Shared error kinds and helpers so callers can branch without knowing
// Ory/Keycloak (or future provider) details.
package provider

import (
	"errors"
	"fmt"
)

// ErrorKind is a stable classification of provider failures.
type ErrorKind string

const (
	ErrNotFound         ErrorKind = "not_found"
	ErrAlreadyExists    ErrorKind = "already_exists"
	ErrInvalidArgument  ErrorKind = "invalid_argument"
	ErrUnavailable      ErrorKind = "unavailable"
	ErrPermissionDenied ErrorKind = "permission_denied"
	ErrUnsupported      ErrorKind = "unsupported" // capability missing
	ErrConflict         ErrorKind = "conflict"
)

// ProviderError carries a stable kind plus optional provider detail.
type ProviderError struct {
	Kind     ErrorKind
	Message  string
	Provider string // "ory", "keycloak", …
	Cause    error
}

func (e *ProviderError) Error() string {
	if e == nil {
		return "<nil>"
	}
	base := e.Message
	if e.Provider != "" {
		base = fmt.Sprintf("%s: %s", e.Provider, base)
	}
	if e.Cause != nil {
		return base + ": " + e.Cause.Error()
	}
	return base
}

func (e *ProviderError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// Is reports whether target matches this error's kind (for errors.Is).
func (e *ProviderError) Is(target error) bool {
	t, ok := target.(*ProviderError)
	if !ok || e == nil || t == nil {
		return false
	}
	return e.Kind == t.Kind
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// IsNotFound reports whether err is (or wraps) a not-found provider error.
func IsNotFound(err error) bool {
	return kindIs(err, ErrNotFound)
}

// IsAlreadyExists reports whether err is (or wraps) an already-exists error.
func IsAlreadyExists(err error) bool {
	return kindIs(err, ErrAlreadyExists)
}

// IsUnsupported reports whether err is (or wraps) an unsupported-capability error.
func IsUnsupported(err error) bool {
	return kindIs(err, ErrUnsupported)
}

// IsInvalidArgument reports whether err is (or wraps) an invalid-argument error.
func IsInvalidArgument(err error) bool {
	return kindIs(err, ErrInvalidArgument)
}

func kindIs(err error, kind ErrorKind) bool {
	var pe *ProviderError
	if !errors.As(err, &pe) {
		return false
	}
	return pe.Kind == kind
}

// NewUnsupported returns a ProviderError for a missing capability.
func NewUnsupported(providerName, capability string) error {
	return &ProviderError{
		Kind:     ErrUnsupported,
		Message:  fmt.Sprintf("capability %q is not supported", capability),
		Provider: providerName,
	}
}
