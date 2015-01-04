package sodium

import "fmt"


// #include <stdio.h>
// #include <sodium.h>
import "C"

// BoxPublicKeyBytes returns the expected size, in bytes, of the public keys for the box functions.
func BoxPublicKeyBytes() int {
    return int(C.crypto_box_publickeybytes())
}

// BoxSecretKeyBytes returns the expected size, in bytes, of the secret keys for the box functions.
func BoxSecretKeyBytes() int {
    return int(C.crypto_box_secretkeybytes())
}

// BoxBeforeNmBytes specifies the size, in bytes, of the intermediate key that is generated from
// a given pair of public and secret keys.
func BoxBeforeNmBytes() int {
    return int(C.crypto_box_beforenmbytes())
}

// BoxNonceBytes specifies the size, in bytes, of the nonce used in the crypto_box functions.
func BoxNonceBytes() int {
    return int(C.crypto_box_noncebytes())
}

func BoxBoxZeroBytes() int {
    return int(C.crypto_box_boxzerobytes())
}

// BoxMacBytes specifies the size, in bytes, of the MAC (Message Authentication Code) which is
// inserted into the cipher text to enable the message to be validated prior to decrypting it.
func BoxMacBytes() int {
    return int(C.crypto_box_macbytes())
}


// BoxZeroBytes specifies the number of zero bytes of padding which must be present at the
// start of each message buffer for the box functions, except for the "Easy" version.
func BoxZeroBytes() int {
    return int(C.crypto_box_zerobytes())
}

// BoxKeyPair generates a new public/secret key pair, returning them in the passed buffers.
func BoxKeyPair(pkOut, skOut []byte) int {
    checkSize(pkOut, BoxPublicKeyBytes(), "public key")
    checkSize(skOut, BoxSecretKeyBytes(), "secret key")

    return int(C.crypto_box_keypair((*C.uchar)(&pkOut[0]), (*C.uchar)(&skOut[0])))
}


// BoxBeforeNm is the first have of the box operation and generates a unique key per
// public, secret key pair (recipient, sender). The key is returned in KeyOut which can
// then be pssed to BoxAfterNm or BoxOpenAfterNm. The same key can be used for all messages between
// the same recipient/sender (same key pairs) provided that a unique nonce is used each time.
// This function is an optimization as it allows the shared key to be generated once for
// multiple messages.
//
// Returns 0 on sucess, non-zero result on error.
func BoxBeforeNm(keyOut []byte, pk, sk [] byte) int {
    checkSize(keyOut, BoxBeforeNmBytes(), "key output")
    checkSize(pk, BoxPublicKeyBytes(), "public key")
    checkSize(sk, BoxSecretKeyBytes(), "secret key")

    return int(C.crypto_box_beforenm((*C.uchar)(&keyOut[0]), (*C.uchar)(&pk[0]), (*C.uchar)(&sk[0])))
}


func BoxAfterNm(cypherTextOut []byte, message []byte, nonce, key []byte) int {
    checkSize(cypherTextOut, len(message), "cypher text output");
    checkSize(nonce, BoxNonceBytes(), "nonce")
    checkSize(key, BoxBeforeNmBytes(), "intermediate key")

    return int(C.crypto_box_afternm((*C.uchar)(&cypherTextOut[0]),
        (*C.uchar)(&message[0]), (C.ulonglong)(len(message)),
        (*C.uchar)(&nonce[0]),
        (*C.uchar)(&key[0])))
}

func BoxOpenAfterNm(messageOut []byte, cypherText []byte, nonce, key []byte) int {
    checkSize(messageOut, len(cypherText), "message output")
    checkSize(nonce, BoxNonceBytes(), "nonce")
    checkSize(key, BoxBeforeNmBytes(), "key")

    return int(C.crypto_box_open_afternm(
        (*C.uchar)(&messageOut[0]),
        (*C.uchar)(&cypherText[0]), (C.ulonglong)(len(cypherText)),
        (*C.uchar)(&nonce[0]),
        (*C.uchar)(&key[0])))
}

func Box(cypherTextOut []byte, message []byte, nonce, pk, sk []byte) int {
    checkSize(cypherTextOut, len(message), "cypher text output");
    checkSize(nonce, BoxNonceBytes(), "nonce")
    checkSize(pk, BoxPublicKeyBytes(), "public key")
    checkSize(sk, BoxSecretKeyBytes(), "secret key")

    return int(C.crypto_box((*C.uchar)(&cypherTextOut[0]),
        (*C.uchar)(&message[0]), (C.ulonglong)(len(message)),
        (*C.uchar)(&nonce[0]),
        (*C.uchar)(&pk[0]),
        (*C.uchar)(&sk[0])))
}

func BoxOpen(messageOut []byte, cypherText []byte, nonce, pk, sk []byte) int {
    checkSize(messageOut, len(cypherText), "message output")
    checkSize(nonce, BoxNonceBytes(), "nonce")
    checkSize(pk, BoxPublicKeyBytes(), "public key")
    checkSize(sk, BoxSecretKeyBytes(), "secret key")

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
