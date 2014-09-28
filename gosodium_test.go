package gosodium

import "testing"
import "bytes"
import "github.com/neuegram/GoSodium/sodium"

// TestKeyGeneration verifies only that the public/secret keys are not the same (ie, not all zeros)
// and that they can be successfully passed to the lower-level functions. No other checks are made.
func TestKeyGeneration(t *testing.T) {
	allocSize := 15 + sodium.BoxZeroBytes()
	msg := make([]byte, allocSize)
	ct := make([]byte, allocSize)
	pk1, sk1 := NewKeyPair()
	nonce := NewBoxNonce()

	if bytes.equal(pk1, sk1) {
		t.Fatail("Somehow pk1 and sk1 are the same?!")
	}

	sodium.MemZero(msg[:sodium.BoxZeroBytes()])

	// This just verifies that we can pass the generated keys to the lower level functions directly.
	r1 := sodium.Box(ct, msg, nonce, pk1, sk1)
	if r1 != 0 {
		t.Fatal("Crypto box encrypt failed, got ", r1, " expected 0")
	}

	t.Log("TestKeyGeneration passed")
}
