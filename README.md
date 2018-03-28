number
======


`number` tells you about any given numbers, what `file` would tell you
about a file.

It shows you all kind of properties and allows you to transform numbers between
various encodings. Input encodings are: hex, dec, base64 BIGNUM's and base64 MPI's.

Its in an early stage and the match database needs to be populated. The SSH moduli check
is of limited use, as parts of the file are unique to your own machine. Nevertheless,
the OpenSSH project comes with a moduli DB, so `number` also uses this to check
for matching numbers. Note that on some systems the moduli file is only
readable by root.

