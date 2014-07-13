package sodium

import "testing"
import "bytes"


func TestCryptoBox(t *testing.T) {
    messageSizes := []int { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 63, 64,
        65, 95, 96, 97, 127, 128, 129, 1023, 1024, 1025 }
    const maxMessageSize = 1025+32      // 32 == CryptoBox_ZeroBytes constant

    msgBuf := make([]byte, maxMessageSize)
    cypherBuf := make([]byte, maxMessageSize)
    resultBuf := make([]byte, maxMessageSize)
    pk1 := make([]byte, CryptoBox_PublicKeyBytes())
    sk1 := make([]byte, CryptoBox_SecretKeyBytes())
    pk2 := make([]byte, CryptoBox_PublicKeyBytes())
    sk2 := make([]byte, CryptoBox_SecretKeyBytes())
    nonce := make([]byte, CryptoBox_NonceBytes())

    CryptoBox_KeyPair(pk1, sk1);
    CryptoBox_KeyPair(pk2, sk2);
    for _, size := range messageSizes {
        t.Log("Running message size ", size)
        // These functions require the first MacBytes of the message buffer to be zeros.
        allocSize := size + CryptoBox_ZeroBytes()
        msg := msgBuf[:allocSize]
        ct := cypherBuf[:allocSize]
        result := resultBuf[:allocSize]
        SodiumMemZero(msg[:CryptoBox_ZeroBytes()])
        RandomBytes(msg[CryptoBox_ZeroBytes():]) // Leave first MacBytes() as zeros.
        RandomBytes(nonce)

        r1 := CryptoBox(ct, msg, nonce, pk1, sk2)
        if r1 != 0 {
            t.Fatal("Crypto box encrypt failed, got ", r1, " expected 0")
        }
        r2 := CryptoBox_Open(result, ct, nonce, pk2, sk1)
        if r2 != 0 {
            t.Fatal("Crypto box open failed, got ", r2, " expected 0")
        }
        if !bytes.Equal(msg, result) {
            t.Fatalf("Byte arrays are not the same, starting bytes are %x, %x, %x, %x vs %x, %x, %x, %x",
                result[0], result[1], result[2], result[3], msg[0], msg[1], msg[2], msg[3])
        }
    }
    t.Log("TestCryptoBox passed")
}



