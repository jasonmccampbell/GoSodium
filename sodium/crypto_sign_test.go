package sodium

import (
	"bytes"
	"testing"
)

func TestSignAndVerify(t *testing.T) {

	t.Logf("SignBytes is %v", SignBytes())
	t.Logf("SignSeedBytes is %v", SignSeedBytes())
	t.Logf("SignPublicKeyBytes is %v", SignPublicKeyBytes())
	t.Logf("SignSecretKeyBytes is %v", SignSecretKeyBytes())

	Pk := make([]byte, SignPublicKeyBytes())
	Sk := make([]byte, SignSecretKeyBytes())
	ret := SignKeyPair(Pk, Sk)
	if ret != 0 {
		t.Fatalf("bad result making alice sign pair: %v", ret)
	}

	messageSizes := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 63,
		64, 65, 95, 96, 97, 127, 128, 129, 1023, 1024, 1025, 2047, 3072, 4096,
		5000, 18000, 32768, 128000}

	for i := 0; i < len(messageSizes); i++ {
		// new message
		msg := make([]byte, messageSizes[i])
		RandomBytes(msg)

		// sign message
		signed := make([]byte, len(msg)+SignBytes())
		ret = Sign(signed, msg, Sk)
		if ret != 0 {
			t.Fatalf("bad result signing: %v", ret)
		}

		// verify message
		msg2 := make([]byte, len(msg))
		ret = SignOpen(msg2, signed, Pk)
		if ret != 0 {
			t.Fatalf("bad result verifying: %v", ret)
		}
		if !bytes.Equal(msg, msg2) {
			t.Fatalf("different unsealed message")
		}

		// try corrupting the message at various points
		corruptedCopy := make([]byte, len(signed))
		for c := 0; c < len(signed); c += 100 {
			copy(corruptedCopy, signed)

			corruptedCopy[c] += 1 // wrap around

			ret = SignOpen(msg2, corruptedCopy, Pk)
			if ret == 0 {
				t.Fatalf("good result verifying corrupted copy: %v", ret)
			}
		}
	}

}
