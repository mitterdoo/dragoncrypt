# dragoncrypt
A lightweight stream cipher with HMAC validity checking

A unique feature about this stream cipher, is that the stream being XOR'd with the plaintext *changes and depends on the plaintext contents*. This allows for true randomization using a truly-random (discarded when decrypted) string of bytes at the beginning.

Below are diagrams detailing the basic structure of the algorithm
![Encryption Diagram](http://mitterdoo.net/u/2019-05/31024f12-460c-466b-97a5-a4bff8c8bdcb.png)
![Decryption Diagram](http://mitterdoo.net/u/2019-05/52d16498-3142-4919-b75a-b912876b0562.png)
