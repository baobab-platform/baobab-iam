package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

func closedChecks(checks map[string]bool, required []string) bool {
	if len(checks) != len(required) {
		return false
	}
	for _, id := range required {
		if _, ok := checks[id]; !ok {
			return false
		}
	}
	return true
}

type syncedWriter interface {
	io.WriteCloser
	Sync() error
}

// Preserve close failures even when writing or syncing already failed.
func writeSynced(f syncedWriter, data []byte) (err error) {
	defer func() { err = errors.Join(err, f.Close()) }()
	n, err := f.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return f.Sync()
}

func syncDirectory(name string) (err error) {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	return f.Sync()
}

// Both receipt schemas share one private, atomic publication boundary.
// Callers validate the closed schema before any data reaches the filesystem.
func publishBundle(directory string, receipt any) error {
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err = os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	pending, err := os.MkdirTemp(directory, ".pending-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(pending)
	write := func(name string, bytes []byte) error {
		f, err := os.OpenFile(filepath.Join(pending, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		return writeSynced(f, bytes)
	}
	if err = write("receipt.json", data); err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	if err = write("receipt.sha256", []byte(hex.EncodeToString(digest[:])+"  receipt.json\n")); err != nil {
		return err
	}
	for _, dir := range []string{pending, directory} {
		if err = syncDirectory(dir); err != nil {
			return err
		}
	}
	nonce := make([]byte, 12)
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	// This is the final fallible operation: no visible PASS on earlier failure.
	return os.Rename(pending, filepath.Join(directory, "run-"+hex.EncodeToString(nonce)))
}
