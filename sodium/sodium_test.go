package sodium

import "bytes"
import "testing"

func TestRandomBytes(t *testing.T) {
    SodiumInit()

    sizes := []int { 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 127, 128, 129, 1023, 1024, 1025 }
    
    for _, size := range sizes {
        buf1 := make([]byte, size)
        buf2 := make([]byte, size)
        if !bytes.Equal(buf1, buf2) {
            t.Fatal("buf1 and buf2 aren't zero'd.")
        }
        RandomBytes(buf1)
        if bytes.Equal(buf1, buf2) {
            t.Fatal("buf1 and buf2 are still the same.")
        }
        copy(buf2, buf1)
        if !bytes.Equal(buf1, buf2) {
            t.Fatal("Copy failed, arrays aren't the same.")
        }
        RandomBytes(buf2)
        if bytes.Equal(buf1, buf2) {
            t.Fatal("Second call to RandomBytes failed.")
        }
    }
}
