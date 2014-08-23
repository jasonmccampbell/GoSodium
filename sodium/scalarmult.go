package sodium

// #cgo CFLAGS: -I/home/action/.parts/packages/libsodium/0.6.0/include
// #cgo LDFLAGS: /home/action/.parts/packages/libsodium/0.6.0/lib/libsodium.a
// #include <stdio.h>
// #include <sodium.h>
import "C"

func ScalarMultBytes() int {
	return int(C.crypto_scalarmult_bytes())
}

func ScalarMultScalarBytes() int {
	return int(C.crypto_scalarmult_scalarbytes())
}

func ScalarMultBase(pkOut []byte, skIn []byte) int {
	checkSize(pkOut, BoxPublicKeyBytes(), "public key")
	checkSize(skIn, BoxSecretKeyBytes(), "secret key")

	return int(C.crypto_scalarmult_base((*C.uchar)(&pkOut[0]), (*C.uchar)(&skIn[0])))
}
