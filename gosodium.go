// GoSodium is a higher level, go-ideomatic wrapper on top of the LibSodium library.
// The functions provided here handle much of the memory allocation and error checking,
// raising panic calls in cases where a function fails. For low-level access to the
// full libsodium library use GoSodium.sodium, which attempts to faithfully reproduce
// the libsodium interface.
package gosodium

import "sodium"
import "fmt"

func NewKeyPair() : (pk, sk []byte) {
    pk := make([]byte, sodium.CryptoBox_PublickKeyBytes())
    sk := make([]byte, sodium.CryptoBox_SecretKeyBytes())
    r := sodium.CryptoBox_KeyPair(pk, sk)
    if r != 0 {
        panic(fmt.Sprintf("Key pair generation failed with result %d, expected 0.", r))
    }
    return pk, sk
}

type PublicKey []byte
type SecretKey []byte
type SymmetricKey []byte

func AllocPublicKey () : PublicKey {
    return make([]byte, sodium.BoxPublicKeyBytes())
}

func AllocSecretKey () : SecretKey {
    return make([]byte, sodium.BoxSecretKeyBytes())
}

func AllocSymmetricKey () : SymmetricKey {
    return make([]byte, sodium.SecretBoxKeyBytes())
}
