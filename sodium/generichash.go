package sodium

import "fmt"

// #cgo CFLAGS: -I/home/action/.parts/packages/libsodium/0.6.0/include
// #cgo LDFLAGS: /home/action/.parts/packages/libsodium/0.6.0/lib/libsodium.a
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

func GenericHash(hashOut []byte, message []byte, key []byte) int {
	checkSize(hashOut, GenericHashBytes(), "hash output")
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

func checkKeySize(key []byte) {
	if !(len(key) > GenericHashKeyBytesMin() && len(key) < GenericHashKeyBytesMax()) && key != []byte(nil) {
		panic(fmt.Sprintf("Incorrect key buffer size, expected (%d - %d), got (%d).",
			GenericHashKeyBytesMin(), GenericHashKeyBytesMax(), len(key)))
	}
}
