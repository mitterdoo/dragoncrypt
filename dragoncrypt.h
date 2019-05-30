/*
	dragoncrypt.h
	Lightweight stream cipher with HMAC validity checking.

	Author: Connor "mitterdoo" Ashcroft
 */

#ifndef __DRAGONCRYPT_LIB__

#define __DRAGONCRYPT_LIB__
#include <stdio.h>


#ifndef DRGC_32BIT
	typedef unsigned long long keyType;
#else
	typedef unsigned long keyType;  // PRNG, HMAC, and encryption keys all use this type
#endif

extern const int dragoncryptKeySize; // size of keyType in bytes. defined in source

/* Encrypt `input` file stream using `key` as the key, outputting to `output` file stream.
 * A HMAC is appended to the end, with size = sizeof(keyType)
 * It is strongly encouraged to use an initialization vector of truly-random bytes, which will be prepended to the encrypted message.
 * For 32-bit encryption, at least 3 IV bytes should be used. For 64-bit, at least 7 bytes should be used.
 */
extern void fencrypt(FILE* input, FILE* output, keyType key, unsigned long size, const char* IV, unsigned long IVsize);

/* Decrypt `input` file stream using `key` as the key, where `size` is the length of the encrypted message (with HMAC), outputting to `output` file stream, while discarding the first `IVsize` bytes.
 * Returns 1 if the message is valid
 */
extern int fdecrypt(FILE* input, FILE* output, keyType key, unsigned long size, unsigned long IVsize);

/* Encrypt `input` char buffer using `key` as the key, where `size` is the length of the plaintext char buffer, outputting to `output` char buffer.
 * A HMAC is appended to the end, with size = sizeof(keyType)
 * It is strongly encouraged to use an initialization vector of truly-random bytes, which will be prepended to the encrypted message.
 * For 32-bit encryption, at least 3 IV bytes should be used. For 64-bit, at least 7 bytes should be used.
 */
extern void sencrypt(const char* input, char* output, keyType key, unsigned long size, const char* IV, unsigned long IVsize);

/* Decrypt `input` char buffer using `key` as the key, where `size` is the length of the encrypted message (with HMAC), outputting to `output` char buffer, while discarding the first `IVsize` bytes.
 * Returns 1 if the message is valid
 */
extern int sdecrypt(const char* input, char* output, keyType key, unsigned long size, unsigned long IVsize);

#endif
