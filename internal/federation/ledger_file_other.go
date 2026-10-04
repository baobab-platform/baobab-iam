//go:build !linux

package federation

import "os"

// The durable federation runtime is supported on Linux. Other platforms must
// provide equivalent atomic no-follow, ownership and regular-file checks before
// enabling this implementation; a permissive portability fallback is unsafe.
func privateLedgerFile(string, int, os.FileMode) (*os.File, error) {
	return nil, ErrUnsupported
}
