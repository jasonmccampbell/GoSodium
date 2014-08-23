package sodium

// #cgo CFLAGS: -I/usr/local/include
// #cgo LDFLAGS: /usr/local/lib/libsodium.a
// #include <stdio.h>
// #include <sodium.h>
import "C"

func SignBytes() int {
	return int(C.crypto_sign_bytes())
}

func SignSeedBytes() int {
	return int(C.crypto_sign_seedbytes())
}

func SignPublicKeyBytes() int {
	return int(C.crypto_sign_publickeybytes())
}

func SignSecretKeyBytes() int {
	return int(C.crypto_sign_secretkeybytes())
}

func SignSeedKeyPair(pkOut []byte, skOut []byte, seed []byte) int {
	return int(C.crypto_sign_seed_keypair((*C.uchar)(&pkOut[0]), (*C.uchar)(&skOut[0]), (*C.uchar)(&seed[0])))
}

func SignKeyPair(pkOut []byte, skOut []byte) int {
	return int(C.crypto_sign_keypair((*C.uchar)(&pkOut[0]), (*C.uchar)(&skOut[0])))
}

func Sign(sealedMessageOut []byte, message []byte, sk []byte) int {
	checkSize(sealedMessageOut, SignBytes()+len(message), "sealed message output")
	checkSize(sk, SignSecretKeyBytes(), "secret key")

	lenSealedMessageOut := (C.ulonglong)(len(sealedMessageOut))

	return int(C.crypto_sign(
		(*C.uchar)(&sealedMessageOut[0]), (*C.ulonglong)(&lenSealedMessageOut),
		(*C.uchar)(&message[0]), (C.ulonglong)(len(message)),
		(*C.uchar)(&sk[0])))
}

func SignOpen(messageOut []byte, sealedMessage []byte, pk []byte) int {
	checkSize(messageOut, len(sealedMessage)-SignBytes(), "message output")
	checkSize(pk, SignPublicKeyBytes(), "public key")

	lenMessageOut := (C.ulonglong)(len(messageOut))

	return int(C.crypto_sign_open(
		(*C.uchar)(&messageOut[0]), (*C.ulonglong)(&lenMessageOut),
		(*C.uchar)(&sealedMessage[0]), (C.ulonglong)(len(sealedMessage)),
		(*C.uchar)(&pk[0])))
}
