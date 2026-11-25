package shamir

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSplitCombine(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)
	parts, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	for _, idx := range [][]int{{0, 1, 2}, {4, 2, 0}, {1, 3, 4}, {0, 1, 2, 3, 4}} {
		var sub [][]byte
		for _, i := range idx {
			sub = append(sub, parts[i])
		}
		got, err := Combine(sub)
		if err != nil || !bytes.Equal(got, secret) {
			t.Fatalf("combine %v failed", idx)
		}
	}
	got, _ := Combine(parts[:2])
	if bytes.Equal(got, secret) {
		t.Fatal("two shares must not reveal the secret")
	}
	if _, err := Combine([][]byte{parts[0], parts[0]}); err == nil {
		t.Fatal("duplicate shares accepted")
	}
}
