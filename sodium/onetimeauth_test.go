package sodium

import "testing"

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestOneTimeAuth(t *testing.T) {
	// Scattering of message sizes and likely corner cases.
	messageSizes := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 63, 64,
		65, 95, 96, 97, 127, 128, 129, 1023, 1024, 1025}
	const maxMessageSize = 1025

	msgBuf := make([]byte, maxMessageSize)
	mac1 := make([]byte, OneTimeAuthBytes())
	mac2 := make([]byte, OneTimeAuthBytes())
	key := make([]byte, OneTimeAuthKeyBytes())

	RandomBytes(key)
	RandomBytes(msgBuf)
	for _, size := range messageSizes {
		t.Log("Running message size ", size)
		msg := msgBuf[:size]

		// Simple way, compute the MAC all at once.
		OneTimeAuth(mac1, msg, key)

		// Compute the MAC incrementally.
		state := OneTimeAuthInit(key)
		for i := 0; i < len(msg); i += 7 {
			OneTimeAuthUpdate(state, msg[i:min(i+7, len(msg))])
		}
		OneTimeAuthFinal(state, mac2)

		// The MAC should be the same independent of how it was created.
		if OneTimeAuthVerify(mac1, msg, key) != 0 {
			t.Fatal("Failed to verify mac1 computed as a single-shot")
		}
		if OneTimeAuthVerify(mac2, msg, key) != 0 {
			t.Fatal("Failed to verify mac2 computed incrementally")
		}
	}
}
