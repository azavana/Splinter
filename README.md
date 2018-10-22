# Splinter

Splinter is an encryption program using 7 differents encryption function: RIPEMD160; RC4A; SPRITZ; RC4A_SPRITZ; SHA-256; SHA-384 and
SHA-512.

- 1 Step) The program takes a clear text as an input, use the MD5 hash function to sign the clear message.

- 2 Step) The program choose RANDOMLY one of the function above to encrypt the message.

- 3 Step) The program return the encrypted message an the signature of the clear message.
