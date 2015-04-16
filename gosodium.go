// GoSodium is a higher level, go-ideomatic wrapper on top of the LibSodium library.
// The functions provided here handle much of the memory allocation and error checking,
// raising panic calls in cases where a function fails. For low-level access to the
// full libsodium library use GoSodium.sodium, which attempts to faithfully reproduce
// the libsodium interface.
package gosodium

import "github.com/neuegram/GoSodium/sodium"
import "fmt"

type PublicKey []byte
type SecretKey []byte
type SymmetricKey []byte
type Nonce []byte

func AllocPublicKey() PublicKey {
	return make([]byte, sodium.BoxPublicKeyBytes())
}

func AllocSecretKey() SecretKey {
	return make([]byte, sodium.BoxSecretKeyBytes())
}

func AllocSymmetricKey() SymmetricKey {
	return make([]byte, sodium.SecretBoxKeyBytes())
}

func NewKeyPair() (PublicKey, SecretKey) {
	pk := AllocPublicKey()
	sk := AllocSecretKey()
	r := sodium.BoxKeyPair(pk, sk)
	if r != 0 {
		panic(fmt.Sprintf("Key pair generation failed with result %d, expected 0.", r))
	}
	return pk, sk
}

func NewBoxNonce() Nonce {
	nonce := make([]byte, sodium.BoxNonceBytes())
	sodium.RandomBytes(nonce)
	return nonce
}
