number
======


`number` tells you about any given numbers, what `file` would tell you
about a file.

It shows you all kind of properties and allows you to transform numbers between
various encodings. Input encodings are: hex, dec, base64 BIGNUM's and base64 MPI's.

Its in an early stage and the match database needs to be populated.
If you want to use the match filter for known numbers, you have to install
`number`, otherwise you may just run it from your CWD.

```
$ make
[...]
# make install
# exit
$ ./number -x FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
hash: SHA256
ec: prime256v1 prime,
prime: Yes
match: No
bytes: 32
bits: 256
$ ./number -m AAAAIFrGNdiqOpPns+u9VXaYhrxlHQawzFOw9jvOPD4n0mBL -X
bits: 255
hex: 5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
bytes: 32
match: No
prime: No
ec: prime256v1 b,
hash: No
$
```

