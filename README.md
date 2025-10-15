# dragoncrypt
A lightweight stream cipher with HMAC validity checking

A unique feature about this stream cipher, is that the stream being XOR'd with the plaintext *changes and depends on the plaintext contents*. This allows for true randomization using a truly-random (discarded when decrypted) string of bytes at the beginning.

After running numerous tests on my own machine with a HDD, speeds went up to *133.8 MiB/s* encrypting, and *128.9 MiB/s* decrypting, giving a decryption to encryption speed ratio of roughly 96%. `memtest.c` has been included to test speeds on your machine.

Below are diagrams detailing the basic structure of the algorithm
![Encryption Diagram](http://ranthos.com/u/2019-05/f5531077-6f42-4cc1-9b2a-890dd6ea626e.PNG)
![Decryption Diagram](http://ranthos.com/u/2019-05/638fa77a-82d2-4f82-8600-520aa7fe0741.PNG)
