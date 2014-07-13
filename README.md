
# Introduction
GoSodium is a (work-in-progress) Go language binding for the [LibSodium](https://github.com/jedisct1/libsodium) cryptography 
library. LibSodium is a cross-platform port of the [NaCL library](http://nacl.cr.yp.to/) published by Dan Bernstein and
company implementing the 25519 eliptic curve. These cryptogrpahic methods, and these libraries, are highly regarded as
fast, secure, and free of governmental influences.

This package is primarily for personal use as an excuse to learn Go and get more familiar with cryptography and is
very much a work-in-progress. If it is useful to others, please feel free to use it at your own risk or contribute to
it. If this is a duplicate of other work, please let me know as I am happy to contribute to other projects to avoid
duplicatating efforts.

# Status

I am (slowly) wrapping parts of the library as I have time / need so many parts are yet-unwrapped. This table provides
a summary of the functionality in each of the LibSodium library and whether they are included.

Module             | Wrap status | Test coverage | Function
-----------------  | ----------- | ------------- | --------------------------------
crypto_box         | Wrapped     | Partial       | Encrypts and authenticates a message using a key pair and nonce.
crypto_onetimeauth | Not wrapped | N/A           | Signs a message using a symmetric key and nonce pair.
crypto_secret_box  | Wrapped     | Partial       | Encrypts and authenticates a message using a symmetric key and nonce
crypto_streaming   | Not wrapped | N/A           | Generates a randomized stream of bits to be XOR'd with a message
randombytes        | Wrapped     | Yes           | Fills a byte array with cryptographic-quality random values
sodium             | Partially   | Partial       | Iniiialization and utility methods.

Definitions:

* Key Pair: A pair of keys comprised of the recipient's public key and the senders secret key.
* Symmetric key: A single key which is known to both the sender and recipient(s)


# Getting starts on Nitrous.io

parts install go
parts install libsodium
go get github.com/jasonmccampbell/GoSodium

Installing libsodium puts it in ~/.parts/packages/libsodium-0.6.0. This is the path that is hardcoded into
the remaining .go files. 

# Building and testing GoSodium

