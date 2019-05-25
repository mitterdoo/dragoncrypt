/*
	dragoncrypt.h
	Lightweight stream cipher with HMAC authentication.

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
 * It is strongly encouraged to use a truly-random string of bytes at the beginning as an initialization vector. More bytes = stronger security
 */
extern void fencrypt(FILE* input, FILE* output, const keyType* key);

/* Decrypt `input` file stream using `key` as the key, where `size` is the length of the encrypted message (with HMAC), outputting to `output` file stream.
 * Returns 1 if the message is valid
 */
extern int fdecrypt(FILE* input, FILE* output, const keyType* key, unsigned long size);

/* Encrypt `input` char buffer using `key` as the key, where `size` is the length of the plaintext char buffer, outputting to `output` char buffer.
 * A HMAC is appended to the end, with size = sizeof(keyType)
 * It is strongly encouraged to use a truly-random string of bytes at the beginning as an initialization vector. More bytes = stronger security
 */
extern void sencrypt(const char* input, char* output, const keyType* key, unsigned long size);

/* Decrypt `input` char buffer using `key` as the key, where `size` is the length of the encrypted message (with HMAC), outputting to `output` char buffer.
 * Returns 1 if the message is valid
 */
extern int sdecrypt(const char* input, char* output, const keyType* key, unsigned long size);

#endif
