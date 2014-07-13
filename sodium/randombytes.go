package sodium

//import "fmt"
//import "unsafe"

// #cgo CFLAGS: -I../../../../../../../libsodium/include
// #cgo LDFLAGS: /home/action/libsodium/lib/libsodium.a
// #include <stdio.h>
// #include <sodium.h>
import "C"


func RandomBytes(buf []byte) {
    C.randombytes( (*C.uchar)(&buf[0]), C.ulonglong(len(buf)))
}
