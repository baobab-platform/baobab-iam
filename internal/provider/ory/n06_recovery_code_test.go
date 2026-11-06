package ory_test

import "testing"

// A MIME multipart/alternative email commonly repeats one one-time code.
// An unexpected second code must not be chosen by order or by format.
func TestN06CourierCodeIsOneDistinctValueAcrossMimeAlternatives(t *testing.T) {
	testCases := []struct {
		name string
		mail []string
		want string
		denied bool
	}{
		{name: "plain-and-html-agree",mail: []string{
			"BAOBAB_N06_RECOVERY_CODE=12345678\n",
			"<p>BAOBAB_N06_RECOVERY_CODE=<b>12345678</b></p>\n",
		},want:"12345678"},
		{name: "same-code-repeated",mail: []string{
			"BAOBAB_N06_RECOVERY_CODE=12345678\nBAOBAB_N06_RECOVERY_CODE=12345678\n",
		},want:"12345678"},
		{name: "missing-code",mail: []string{"A recovery attempt happened."}},
		{name: "two-conflicting-codes",mail: []string{
			"BAOBAB_N06_RECOVERY_CODE=12345678\nBAOBAB_N06_RECOVERY_CODE=87654321\n",
		},denied:true},
		{name: "disagreeing-mime-alternatives",mail: []string{
			"BAOBAB_N06_RECOVERY_CODE=12345678\n",
			"<p>BAOBAB_N06_RECOVERY_CODE=87654321</p>\n",
		},denied:true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			code,err := n06OneDistinctRecoveryCode(tc.mail)
			if (err!=nil)!=tc.denied || (!tc.denied && code!=tc.want) {
				t.Fatal("recovery code uniqueness invariants violated")
			}
		})
	}
}
