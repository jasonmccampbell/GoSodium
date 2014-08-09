package sodium

//import "fmt"
import "unsafe"

// #cgo CFLAGS: -I/home/action/.parts/packages/libsodium/0.6.0/include
// #cgo LDFLAGS: /home/action/.parts/packages/libsodium/0.6.0/lib/libsodium.a
// #include <stdio.h>
// #include <sodium.h>
import "C"

// Opaque structure representing the internal state of the MAC calculations.
type OneTimeAuthState C.struct_onetimeauth_poly1305_state


// OneTimeAuthBytes returns the size of the authenticator in bytes.
func OneTimeAuthBytes () int {
    return int(C.crypto_onetimeauth_bytes())
}

// OneTimeAuthKeyBytes specifies the number of bytes in the symmetric key
func OneTimeAuthKeyBytes () int {
    return int(C.crypto_onetimeauth_keybytes())
}

// OneTimeAuthPrimivite returns a string identifying which authentication primitive is being used.
// TODO: Not found in my build. 
//func OneTimeAuthPrimitive () string {
//    return C.GoString(crypto_onetimeauth_primitive())
//}

// OneTimeAuth computes a message authentication code (MAC) for the given input buffer and writes
// it to 'out'. 'out' must be a []byte of OneTimeAuthBytes() bytes. 'key' must not be used with
// any other messages.
//
// Returns: 0
func OneTimeAuth (macOut []byte, message []byte, key []byte) int {
    checkSize(macOut, OneTimeAuthBytes(), "MAC output buffer")
    checkSize(key, OneTimeAuthKeyBytes(), "key")

    return int(C.crypto_onetimeauth(
        (*C.uchar)(&macOut[0]),
        (*C.uchar)(&message[0]), (C.ulonglong)(len(message)),
        (*C.uchar)(&key[0])))
}



// OneTimeAuthVerify verifies a message authentication code (MAC) for a given message and key.
//
// Returns: 0 if the MAC authenticates the message, -1 if not.
func OneTimeAuthVerify(mac, message, key []byte) int {
    checkSize(mac, OneTimeAuthBytes(), "MAC")
    checkSize(key, OneTimeAuthKeyBytes(), "key")
    
    return int(C.crypto_onetimeauth_verify(
        (*C.uchar)(&mac[0]),
        (*C.uchar)(&message[0]), (C.ulonglong)(len(message)),
        (*C.uchar)(&key[0])))
}


// OneTimeAuthInit initializes an internal state structure to allow incremental
// computation of a message authentication code.
func OneTimeAuthInit(key []byte) *OneTimeAuthState {
    state := (C.malloc( C.size_t(unsafe.Sizeof(C.struct_onetimeauth_state{})) ))
    C.crypto_onetimeauth_init( (*C.struct_crypto_onetimeauth_poly1305_state)(state), (*C.uchar)(&key[0]))
    return (*OneTimeAuthState)(state)
}


// OneTimeAuthUpdate incrementally updates the MAC computation state with the contents of
// inBuf. Update may be called multiple times while consuming a message.
func OneTimeAuthUpdate(state *OneTimeAuthState, inBuf []byte) {
    statePtr := (unsafe.Pointer)(state)
    C.crypto_onetimeauth_update( (*C.struct_crypto_onetimeauth_poly1305_state)(statePtr), 
                                (*C.uchar)(&inBuf[0]), (C.ulonglong)(len(inBuf)))
}

// OneTimeAuthFinal writes the final message authentication code to macOut based on the
// state computed by OneTimeAuthInit and OneTimeAuthUpdate. Once this function is called
// state is deallocated and may never be accessed again; this function must be called
// exactly once for each call to OneTimeAuthInit to avoid leaking memory.
func OneTimeAuthFinal(state *OneTimeAuthState, macOut []byte) int {
    checkSize(macOut, OneTimeAuthBytes(), "MAC output buffer")
    
    statePtr := (unsafe.Pointer)(state)
    r := int(C.crypto_onetimeauth_final( (*C.struct_crypto_onetimeauth_poly1305_state)(statePtr), 
                                        (*C.uchar)(&macOut[0])))
    C.free(statePtr)
    return r
}
