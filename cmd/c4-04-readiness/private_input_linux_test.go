//go:build linux

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func privateTestCA(t *testing.T) []byte {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestC404TrustUsesOnlyOneProtectedOwnerInode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, privateTestCA(t), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedTransport(path); err != nil {
		t.Fatal("valid owner-private CA denied", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedTransport(path); err == nil {
		t.Fatal("CA must satisfy the private service-file permission contract")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "hardlink")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedTransport(path); err == nil {
		t.Fatal("multi-linked trust file accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedTransport(fifo); err == nil {
		t.Fatal("FIFO trust input accepted")
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 65537)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedTransport(path); err == nil {
		t.Fatal("oversized private CA accepted")
	}
}

func TestC404PrivilegedServiceRefusesAnotherOwnersPrivateCA(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing fixture ownership requires a privileged test process")
	}
	path := filepath.Join(t.TempDir(), "foreign-ca.pem")
	if err := os.WriteFile(path, privateTestCA(t), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 65534, 65534); err != nil {
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EPERM) {
			t.Skip("isolated user namespace cannot represent a second fixture owner")
		}
		t.Fatal(err)
	}
	if _, err := trustedTransport(path); err == nil {
		t.Fatal("root service accepted a trust file writable by another owner")
	}
}
