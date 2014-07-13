package sodium

//import "fmt"
//import "unsafe"

// #cgo CFLAGS: -I/home/action/.parts/packages/libsodium/0.6.0/include
// #cgo LDFLAGS: /home/action/.parts/packages/libsodium/0.6.0/lib/libsodium.a
// #include <stdio.h>
// #include <sodium.h>
import "C"


func RandomBytes(buf []byte) {
    C.randombytes( (*C.uchar)(&buf[0]), C.ulonglong(len(buf)))
}
