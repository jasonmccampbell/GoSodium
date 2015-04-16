package sodium

import "fmt"

// #cgo CFLAGS: -I/usr/local/include/sodium
// #cgo LDFLAGS: /usr/local/lib/libsodium.a
// #include <stdio.h>
// #include <sodium.h>
import "C"

func GenericHashBytesMin() int {
	return int(C.crypto_generichash_bytes_min())
}

func GenericHashBytesMax() int {
	return int(C.crypto_generichash_bytes_max())
}

func GenericHashBytes() int {
	return int(C.crypto_generichash_bytes())
}

func GenericHashKeyBytesMin() int {
	return int(C.crypto_generichash_keybytes_min())
}

func GenericHashKeyBytesMax() int {
	return int(C.crypto_generichash_keybytes_max())
}

func GenericHashKeyBytes() int {
	return int(C.crypto_generichash_keybytes_max())
}

func GenericHashSaltBytes() int {
	return int(C.crypto_generichash_blake2b_saltbytes())
}

func GenericHashPersonalBytes() int {
	return int(C.crypto_generichash_blake2b_personalbytes())
}

func GenericHash(hashOut []byte, message []byte, key []byte) int {
	checkHashOutSize(hashOut)
	checkKeySize(key)
	if key == []byte(nil) {
		return int(C.crypto_generichash(
			(*C.uchar)(&hashOut[0]), (C.size_t)(len(hashOut)),
			(*C.uchar)(&message[0]), (C.ulonglong)(len(message)),
			nil, (C.size_t)(0)))
	}
	return int(C.crypto_generichash(
		(*C.uchar)(&hashOut[0]), (C.size_t)(len(hashOut)),
		(*C.uchar)(&message[0]), (C.ulonglong)(len(message)),
		(*C.uchar)(&key[0]), (C.size_t)(len(key))))
}

func GenericHashSaltPersonal(hashOut []byte, message []byte, key []byte, salt []byte, personal []byte) int {
	checkHashOutSize(hashOut)
	checkKeySize(key)
	checkSize(salt, GenericHashSaltBytes(), "salt")
	checkSize(personal, GenericHashPersonalBytes(), "personal")
	if key == []byte(nil) {
		return int(C.crypto_generichash_blake2b_salt_personal(
			(*C.uchar)(&hashOut[0]), (C.size_t)(len(hashOut)),
			(*C.uchar)(&message[0]), (C.ulonglong)(len(message)),
			nil, (C.size_t)(0),
			(*C.uchar)(&salt[0]),
			(*C.uchar)(&personal[0])))
	}
	return int(C.crypto_generichash_blake2b_salt_personal(
		(*C.uchar)(&hashOut[0]), (C.size_t)(len(hashOut)),
		(*C.uchar)(&message[0]), (C.ulonglong)(len(message)),
		(*C.uchar)(&key[0]), (C.size_t)(len(key)),
		(*C.uchar)(&salt[0]),
		(*C.uchar)(&personal[0])))
}

func checkHashOutSize(hashOut []byte) {
	if !(len(hashOut) > GenericHashBytesMin() && len(hashOut) < GenericHashBytesMax()) {
		panic(fmt.Sprintf("Incorrect hash out buffer size, expected (%d - %d), got (%d).",
			GenericHashBytesMin(), GenericHashBytesMax(), len(hashOut)))
	}
}

func checkKeySize(key []byte) {
	if !(len(key) > GenericHashKeyBytesMin() && len(key) < GenericHashKeyBytesMax()) && key != []byte(nil) {
		panic(fmt.Sprintf("Incorrect key buffer size, expected (%d - %d), got (%d).",
			GenericHashKeyBytesMin(), GenericHashKeyBytesMax(), len(key)))
	}
}
