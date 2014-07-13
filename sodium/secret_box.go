package sodium

import "fmt"


// #cgo CFLAGS: -I../../../../../../../libsodium/include
// #cgo LDFLAGS: /home/action/libsodium/lib/libsodium.a
// #include <stdio.h>
// #include <sodium.h>
import "C"

// SecretBoxKeyBytes specifies the size of the symmetric key used in the secret box functions.
func SecretBoxKeyBytes () int {
    return int(C.crypto_secretbox_keybytes())
}

// SecretBoxNonceBytes specifies the size, in bytes, of the nonce to be used with the secret box functions.
func SecretboxNonceBytes () int {
    return int(C.crypto_secretbox_noncebytes())
}

// SecretBoxZeroBytes specifies the number of zero-byte padding which must be prsent at the start of
// the message buffers passed to the non-easy version of the functions.
func SecretBoxZeroBytes () int {
    return int(C.crypto_secretbox_zerobytes())
}


// SecretBoxMacBytes specifies the size, in bytes, of the MAC (Message Authentication Code) which
// is inserted at the start of the cypher text.
func SecretBoxZeroBytes () int {
    return int(C.crypto_secretbox_macbytes())
}


// SecretBox takes a message buffer, a random nonce, and a key and writes the encrypted, authenticated
// cypher text into the cypherTextOut buffer. The message buffer must have SecretBoxZeroBytes() worth
// of zero-padding at the start of it. The key may be reused across messages, but the nonce must be
// used only once for a given key. \
//
// Returns: 0 on success, non-zero on failure.
func SecretBox (cypherTextOut, message, nonce, key []byte) int {
    checkSize(cypherTextOut, len(message), "cypher text output");
    checkSize(nonce, SecretBoxNonceBytes(), "nonce")
    checkSize(key, SecretBoxPublicKeyBytes(), "key")

    return int(C.crypto_secretbox(
        (*C.uchar)(&cypherTextOut[0]),
        (*C.uchar)(&message[0]), (C.ulonglong)(len(message)),
        (*C.uchar)(&nonce[0]),
        (*C.uchar)(&key[0])))
}

// SecretBoxOpen opens the authenticated cypher text produced by SecretBox and returns the original
// message plain text. The cypher text is authenticated prior to decryption to ensure it has not
// been modified from the original. The messageOut buffer must be the same size as the cypherText
// buffer and will be padded with SecretBoxZeroBytes() worth of leading zero bytes.
//
// Returns: 0 on success, non-zero on failure
func SecretBoxOpen (messageOut, cypherText, nonce, key []byte) int {
    checkSize(messageOut, len(cypherText), "message output");
    checkSize(nonce, SecretBoxNonceBytes(), "nonce")
    checkSize(key, SecretBoxPublicKeyBytes(), "key")

    return int(C.crypto_secretbox_open(
        (*C.uchar)(&messageOut[0]),
        (*C.uchar)(&cypherText[0]),
        (*C.uchar)(&nonce[0]),
        (*C.uchar)(&key[0])))
}
