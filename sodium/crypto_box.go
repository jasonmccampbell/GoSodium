package sodium

import "fmt"


// #cgo CFLAGS: -I../../../../../../../libsodium/include
// #cgo LDFLAGS: /home/action/libsodium/lib/libsodium.a
// #include <stdio.h>
// #include <sodium.h>
import "C"

// CryptoBoxPublicKeyBytes returns the expected size, in bytes, of the public keys for the box functions.
func CryptoBoxPublicKeyBytes() int {
    return int(C.crypto_box_publickeybytes())
}

// CryptoBoxSecretKeyBytes returns the expected size, in bytes, of the secret keys for the box functions.
func CryptoBoxSecretKeyBytes() int {
    return int(C.crypto_box_secretkeybytes())
}

// CryptoBoxBeforeNmBytes specifies the size, in bytes, of the intermediate key that is generated from
// a given pair of public and secret keys.
func CryptoBoxBeforeNmBytes() int {
    return int(C.crypto_box_beforenmbytes())
}

// CryptoBoxNonceBytes specifies the size, in bytes, of the nonce used in the crypto_box functions.
func CryptoBoxNonceBytes() int {
    return int(C.crypto_box_noncebytes())
}

func CryptoBoxBoxZeroBytes() int {
    return int(C.crypto_box_boxzerobytes())
}

// CryptoBoxMacBytes specifies the size, in bytes, of the MAC (Message Authentication Code) which is
// inserted into the cipher text to enable the message to be validated prior to decrypting it.
func CryptoBoxMacBytes() int {
    return int(C.crypto_box_macbytes())
}


// CryptoBoxZeroBytes specifies the number of zero bytes of padding which must be present at the
// start of each message buffer for the box functions, except for the "Easy" version.
func CryptoBoxZeroBytes() int {
    return int(C.crypto_box_zerobytes())
}

// CryptoBoxKeyPair generates a new public/secret key pair, returning them in the passed buffers.
func CryptoBoxKeyPair(pkOut, skOut []byte) int {
    checkSize(pkOut, CryptoBoxPublicKeyBytes(), "public key")
    checkSize(skOut, CryptoBoxSecretKeyBytes(), "secret key")

    return int(C.crypto_box_keypair((*C.uchar)(&pkOut[0]), (*C.uchar)(&skOut[0])))
}


// CryptoBoxBeforeNm is the first have of the box operation and generates a unique key per
// public, secret key pair (recipient, sender). The key is returned in KeyOut which can
// then be pssed to CryptoBoxAfterNm or CryptoBoxOpenAfterNm. The same key can be used for all messages between
// the same recipient/sender (same key pairs) provided that a unique nonce is used each time.
// This function is an optimization as it allows the shared key to be generated once for
// multiple messages.
//
// Returns 0 on sucess, non-zero result on error.
func CryptoBoxBeforeNm(keyOut []byte, pk, sk [] byte) int {
    checkSize(keyOut, CryptoBoxBeforeNmBytes(), "key output")
    checkSize(pk, CryptoBoxPublicKeyBytes(), "public key")
    checkSize(sk, CryptoBoxSecretKeyBytes(), "secret key")

    return int(C.crypto_box_beforenm((*C.uchar)(&keyOut[0]), (*C.uchar)(&pk[0]), (*C.uchar)(&sk[0])))
}


func CryptoBoxAfterNm(cypherTextOut []byte, message []byte, nonce, key []byte) int {
    checkSize(cypherTextOut, len(message) + CryptoBoxMacBytes(), "cypher text output");
    checkSize(nonce, CryptoBoxNonceBytes(), "nonce")
    checkSize(key, CryptoBoxBeforeNmBytes(), "intermediate key")

    return int(C.crypto_box_afternm((*C.uchar)(&cypherTextOut[0]),
        (*C.uchar)(&message[0]), (C.ulonglong)(len(message)),
        (*C.uchar)(&nonce[0]),
        (*C.uchar)(&key[0])))
}

func CryptoBoxOpenAfterNm(messageOut []byte, cypherText []byte, nonce, key []byte) int {
    checkSize(messageOut, len(cypherText)-CryptoBoxMacBytes(), "message output")
    checkSize(nonce, CryptoBoxNonceBytes(), "nonce")
    checkSize(key, CryptoBoxBeforeNmBytes(), "key")

    return int(C.crypto_box_open_afternm(
        (*C.uchar)(&messageOut[0]),
        (*C.uchar)(&cypherText[0]), (C.ulonglong)(len(cypherText)),
        (*C.uchar)(&nonce[0]),
        (*C.uchar)(&key[0])))
}

func CryptoBox(cypherTextOut []byte, message []byte, nonce, pk, sk []byte) int {
    checkSize(cypherTextOut, len(message), "cypher text output");
    checkSize(nonce, CryptoBoxNonceBytes(), "nonce")
    checkSize(pk, CryptoBoxPublicKeyBytes(), "public key")
    checkSize(sk, CryptoBoxSecretKeyBytes(), "secret key")

    return int(C.crypto_box((*C.uchar)(&cypherTextOut[0]),
        (*C.uchar)(&message[0]), (C.ulonglong)(len(message)),
        (*C.uchar)(&nonce[0]),
        (*C.uchar)(&pk[0]),
        (*C.uchar)(&sk[0])))
}

func CryptoBoxOpen(messageOut []byte, cypherText []byte, nonce, pk, sk []byte) int {
    checkSize(messageOut, len(cypherText), "message output")
    checkSize(nonce, CryptoBoxNonceBytes(), "nonce")
    checkSize(pk, CryptoBoxPublicKeyBytes(), "public key")
    checkSize(sk, CryptoBoxSecretKeyBytes(), "secret key")

    return int(C.crypto_box_open(
        (*C.uchar)(&messageOut[0]),
        (*C.uchar)(&cypherText[0]), (C.ulonglong)(len(cypherText)),
        (*C.uchar)(&nonce[0]),
        (*C.uchar)(&pk[0]),
        (*C.uchar)(&sk[0])))
}


//
// Internal support functions
//

// checkSize verifies the expected size of an input or output byte array.
func checkSize(buf []byte, expected int, descrip string) {
    if len(buf) != expected {
        panic(fmt.Sprintf("Incorrect %s buffer size, expected (%d), got (%d).", descrip, expected, len(buf)))
    }
}
