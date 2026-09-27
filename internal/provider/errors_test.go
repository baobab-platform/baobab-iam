package provider_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

func TestProviderError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("connection refused")
	err := &provider.ProviderError{
		Kind:     provider.ErrUnavailable,
		Message:  "kratos get identity",
		Provider: "ory",
		Cause:    cause,
	}
	got := err.Error()
	if got == "" || !errors.Is(err, cause) {
		t.Fatalf("Error()=%q Is(cause)=%v", got, errors.Is(err, cause))
	}
}

func TestIsNotFound(t *testing.T) {
	err := &provider.ProviderError{Kind: provider.ErrNotFound, Message: "missing", Provider: "ory"}
	if !provider.IsNotFound(err) {
		t.Fatal("expected IsNotFound")
	}
	wrapped := fmt.Errorf("wrap: %w", err)
	if !provider.IsNotFound(wrapped) {
		t.Fatal("expected IsNotFound on wrapped error")
	}
	if provider.IsNotFound(errors.New("other")) {
		t.Fatal("did not expect IsNotFound")
	}
}

func TestIsUnsupported(t *testing.T) {
	err := provider.NewUnsupported("keycloak", "ProvisionIdentity")
	if !provider.IsUnsupported(err) {
		t.Fatal("expected IsUnsupported")
	}
}

func TestIsAlreadyExistsAndInvalidArgument(t *testing.T) {
	if !provider.IsAlreadyExists(&provider.ProviderError{Kind: provider.ErrAlreadyExists, Message: "x"}) {
		t.Fatal("AlreadyExists")
	}
	if !provider.IsInvalidArgument(&provider.ProviderError{Kind: provider.ErrInvalidArgument, Message: "x"}) {
		t.Fatal("InvalidArgument")
	}
}

func TestExternalSubjectString(t *testing.T) {
	s := provider.ExternalSubject{Issuer: "https://id.example", Subject: "abc"}
	if s.String() != "https://id.example|abc" {
		t.Fatalf("got %q", s.String())
	}
}
