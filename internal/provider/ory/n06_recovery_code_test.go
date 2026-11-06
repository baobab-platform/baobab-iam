package ory_test

import "testing"

// The sealed courier returns one plaintext part per original MIME message.
// A conflicting code in another plaintext delivery must never be guessed.
func TestN06CourierCodeIsOneDistinctValueAcrossMimeAlternatives(t *testing.T) {
	testCases := []struct {
		name   string
		mail   []string
		want   string
		denied bool
	}{
		{name: "repeated-plaintext-deliveries-agree", mail: []string{
			"BAOBAB_N06_RECOVERY_CODE=12345678\n",
			"BAOBAB_N06_RECOVERY_CODE=12345678\r\n",
		}, want: "12345678"},
		{name: "same-code-repeated", mail: []string{
			"BAOBAB_N06_RECOVERY_CODE=12345678\nBAOBAB_N06_RECOVERY_CODE=12345678\n",
		}, want: "12345678"},
		{name: "missing-code", mail: []string{"A recovery attempt happened."}},
		{name: "two-conflicting-codes", mail: []string{
			"BAOBAB_N06_RECOVERY_CODE=12345678\nBAOBAB_N06_RECOVERY_CODE=87654321\n",
		}, denied: true},
		{name: "conflicting-plaintext-deliveries", mail: []string{
			"BAOBAB_N06_RECOVERY_CODE=12345678\n",
			"BAOBAB_N06_RECOVERY_CODE=87654321\r\n",
		}, denied: true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			code, err := n06OneDistinctRecoveryCode(tc.mail)
			if (err != nil) != tc.denied || (!tc.denied && code != tc.want) {
				t.Fatal("recovery code uniqueness invariants violated")
			}
		})
	}
}
