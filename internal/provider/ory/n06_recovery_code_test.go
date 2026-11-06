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
			"Your recovery code: 12345678\n",
			"<p>Your recovery code: <b>12345678</b></p>\n",
		},want:"12345678"},
		{name: "same-code-repeated",mail: []string{
			"Your recovery code: 12345678\nYour recovery code: 12345678\n",
		},want:"12345678"},
		{name: "missing-code",mail: []string{"A recovery attempt happened."}},
		{name: "two-conflicting-codes",mail: []string{
			"Your recovery code: 12345678\nYour recovery code: 87654321\n",
		},denied:true},
		{name: "disagreeing-mime-alternatives",mail: []string{
			"Your recovery code: 12345678\n",
			"<p>Your recovery code: 87654321</p>\n",
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
