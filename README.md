
# Introduction
GoSodium is a (work-in-progress) [Go language](golang.org) binding for the [LibSodium](https://github.com/jedisct1/libsodium) cryptography 
library. LibSodium is a cross-platform port of the [NaCL library](http://nacl.cr.yp.to/) published by Dan Bernstein and
company implementing the 25519 elliptic curve. These cryptographic methods, and these libraries, are highly regarded as
fast, secure, and free of governmental influences.

This package is primarily for personal use as an excuse to learn Go and get more familiar with cryptography and is
very much a work-in-progress. If it is useful to others, please feel free to use it, copy it, or contribute to
it. If this is a duplicate of other work, please let me know as I am happy to contribute to other projects to avoid
redundant efforts.

# Status
I am (slowly) wrapping parts of the library as I have time / need so many parts are yet-unwrapped. This table provides
a summary of the functionality in each module of the LibSodium library and whether they are included.

Module             | Wrap status | Test coverage | Function
-----------------  | ----------- | ------------- | --------------------------------
crypto_auth        | Not wrapped | N/A           | Generates a MAC for a given message and secret key using SHA-series hashes (key may be used across multiple messages)
crypto_box         | Wrapped     | Yes           | Encrypts and authenticates a message using a key pair and nonce
crypto_core        | Not wrapped | N/A           | Core encryption algorithms used by other modules
crypto_generichash | Partially   | N/A           | Cryptographically secure generic hash function
crypto_hash        | Not wrapped | N/A           | Hash function based on SHA512 algorithm
crypto_onetimeauth | Wrapped     | Yes           | Generates a MAC for a given message and shared key using Poly1305 algorithm (key may NOT be reused across messages)
crypto_scalarmult  | Partially   | N/A           | Compute the public key given a secret key previously generated with crypto_box_keypair
crypto_secret_box  | Wrapped     | Partial       | Encrypts and authenticates a message using a shared key and nonce
crypto_sign        | Wrapped     | N/A           | Seals and verifies a message using a key pair
crypto_streaming   | Not wrapped | N/A           | Generates a randomized stream of bits to be XOR'd with a message
randombytes        | Wrapped     | Yes           | Fills a byte array with cryptographic-quality random values
sodium             | Partially   | Partial       | Initialization and utility methods

Definitions:

* Key Pair: A pair of keys comprised of one public key and one secret key. For example, the sender's secret key and
  the recipient's public key, or the sender's public key and the recipient's private key.
* Shared key: A single key which is known to both the sender and recipient(s). In LibSodium it is common to generate
  a shared key from a key pair above. The keys have the property that the symmetric key can be generated from each
  half of a key pair. That is, Alice's public key plus Bob's secret key can be combined to generate the same key as
  Bob's public key and Alice's private key. 


# Getting started on Nitrous.io
One quick way to get started playing with this package is on [Nitrous.io](nitrous.io). This is one of several cloud-based IDEs that also
provide virtual machines to get started with. The VMs seem to be decently performant and the 'parts' utility is a nice way
to quickly bootstrap an environment with Go and LibSodium.

Once you have a machine set up:

    parts install go
    parts install libsodium
    go get github.com/neuegram/GoSodium

Installing libsodium puts it in ~/.parts/packages/libsodium-0.6.0. This is the path that is hardcoded into
the remaining .go files. 

*Note:* The recipes for Go 1.3 and LibSodium are currently pending PRs (#161, 162) to the Nitrous.io parts GitHub
repository (https://github.com/nitrous-io/autoparts/pulls). You will need to explicitly pull these branches until the
changes have been merged.


# Building and testing GoSodium
Once you have a working environment, go to your Go 'src' directory and run the following commands:
```
go install github.com/neuegram/GoSodium/sodium
go test github.com/neuegram/GoSodium/sodium
go install github.com/neuegram/GoSodium
```

If all works as expected, the tests should pass for 'sodium' and everything should be ready for use.

# Contact
Questions? Comments? Requests? Complaints? Feel free to contact me here or via [Google+](https://plus.google.com/+JasonMcCampbell/posts) or Twitter (@jasonmccampbell).


