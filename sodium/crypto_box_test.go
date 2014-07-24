package sodium

import "testing"
import "bytes"
import "fmt"


func tryBoxKeyPair(pkOut, skOut []byte) bool {
    status := true
    defer func() {
        if r := recover(); r != nil {
            fmt.Println("Caught error: ", r)
            status = false
        }
    }()
    BoxKeyPair(pkOut, skOut)
    return status
}

    
func TestBoxKeyPair(t *testing.T) {
    r := tryBoxKeyPair(make([]byte, 4), make([]byte, BoxSecretKeyBytes()))
    if r {
        t.Fatal("BoxKeyPair failed to detect too-short public key buffer")
    }
    
    r = tryBoxKeyPair(make([]byte, BoxPublicKeyBytes()), make([]byte, 5))
    if r {
        t.Fatal("BoxKeyPair failed to detect too-short secret key buffer")
    }
    
    r = tryBoxKeyPair(make([]byte, BoxPublicKeyBytes()), make([]byte, BoxSecretKeyBytes()))
    if !r {
        t.Fatal("BoxKeyPair failed when it should have passed.")
    }
}


func TestCryptoBox(t *testing.T) {
    messageSizes := []int { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 63, 64,
        65, 95, 96, 97, 127, 128, 129, 1023, 1024, 1025 }
    const maxMessageSize = 1025+32      // 32 == Box_ZeroBytes constant

    msgBuf := make([]byte, maxMessageSize)
    cypherBuf := make([]byte, maxMessageSize)
    resultBuf := make([]byte, maxMessageSize)
    pk1 := make([]byte, BoxPublicKeyBytes())
    sk1 := make([]byte, BoxSecretKeyBytes())
    pk2 := make([]byte, BoxPublicKeyBytes())
    sk2 := make([]byte, BoxSecretKeyBytes())
    nonce := make([]byte, BoxNonceBytes())
    key := make([]byte, BoxBeforeNmBytes())
    
    BoxKeyPair(pk1, sk1);
    BoxKeyPair(pk2, sk2);
    for _, size := range messageSizes {
        t.Log("Running message size ", size)
        // These functions require the first MacBytes of the message buffer to be zeros.
        allocSize := size + BoxZeroBytes()
        msg := msgBuf[:allocSize]
        ct := cypherBuf[:allocSize]
        result := resultBuf[:allocSize]
        MemZero(msg[:BoxZeroBytes()])
        RandomBytes(msg[BoxZeroBytes():]) // Leave first MacBytes() as zeros.
        RandomBytes(nonce)

        // Basic coverage of standard box/open functions.
        r1 := Box(ct, msg, nonce, pk1, sk2)
        if r1 != 0 {
            t.Fatal("Crypto box encrypt failed, got ", r1, " expected 0")
        }
        r2 := BoxOpen(result, ct, nonce, pk2, sk1)
        if r2 != 0 {
            t.Fatal("Crypto box open failed, got ", r2, " expected 0")
        }
        if !bytes.Equal(msg, result) {
            t.Fatalf("Byte arrays are not the same, starting bytes are %x, %x, %x, %x vs %x, %x, %x, %x",
                result[0], result[1], result[2], result[3], msg[0], msg[1], msg[2], msg[3])
        }
        
        // Re-try using Before/After functions for pre-computing the shared key.
        r1 = BoxBeforeNm(key, pk1, sk2)
        if r1 != 0 {
            t.Fatal("Crypto box before nm failed, got ", r1, " expected 0")
        }
        r1 = BoxAfterNm(ct, msg, nonce, key)
        if r1 != 0 {
            t.Fatal("Crypto box after nm failed, got ", r1, " expected 0")
        }
        r2 = BoxBeforeNm(key, pk2, sk1)
        if r2 != 0 {
            t.Fatal("Crypto box before nm (call 2) failed, got ", r2, " expected 0")
        }
        r2 = BoxOpenAfterNm(result, ct, nonce, key)
        if r2 != 0 {
            t.Fatal("Crypto box open after nm failed, got ", r2, " expected 0")
        }
        if !bytes.Equal(msg, result) {
            t.Fatalf("Byte arrays using before/after are not the same, starting bytes are %x, %x, %x, %x vs %x, %x, %x, %x",
                result[0], result[1], result[2], result[3], msg[0], msg[1], msg[2], msg[3])
        }
    }
    t.Log("TestBox passed")
}



