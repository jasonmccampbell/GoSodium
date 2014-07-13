

* Getting starts on Nitrous.io

parts install go
parts install libsodium
go get github.com/jasonmccampbell/GoSodium

Installing libsodium puts it in ~/.parts/packages/libsodium-0.6.0. This is the path that is hardcoded into
the remaining .go files. 

* Building and testing GoSodium

