# dragoncrypt
A lightweight stream cipher with HMAC validity checking

A unique feature about this stream cipher, is that the stream being XOR'd with the plaintext *changes and depends on the plaintext contents*. This allows for true randomization using a truly-random (discarded when decrypted) string of bytes at the beginning.

Below are diagrams detailing the basic structure of the algorithm
![Encryption Diagram](http://mitterdoo.net/u/2019-05/f5531077-6f42-4cc1-9b2a-890dd6ea626e.PNG)
![Decryption Diagram](http://mitterdoo.net/u/2019-05/638fa77a-82d2-4f82-8600-520aa7fe0741.PNG)
