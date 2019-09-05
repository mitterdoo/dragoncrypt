/*
	dragoncrypt.c
	Lightweight stream cipher with HMAC validity checking.

	Author: Connor "mitterdoo" Ashcroft
 */

#include "dragoncrypt.h"

#ifndef DRGC_32BIT
	#define shuffle(what) what ^= what << 13; what ^= what >> 7; what ^= what << 17 // simple 64-bit xorshift
	#define IPAD 0x4613A6F6B45951C6ull
	#define OPAD 0x29E8FF4949B2863Dull
#else
	#define shuffle(what) what ^= what << 13; what ^= what >> 17; what ^= what << 5 // simple 32-bit xorshift
	#define IPAD 0xB45951C6ul
	#define OPAD 0x49B2863Dul
#endif

static keyType r_seed = 1;  // never initialize to zero
const int dragoncryptKeySize = sizeof(keyType);

// takes thisByte, lshifts by a random amount, and then xors with HMAC.
// after that, HMAC is shuffled with xorshift
#define calcHash(thisByte, hmac, counter) hmac ^= (keyType)( ( keyType )( thisByte&0xFF ) << ( counter = (counter+sizeof(char)) % ( sizeof(keyType)*8-sizeof(char)) )); shuffle(hmac)

/* Encrypts a single byte, and adjusts the HMAC accordingly
 */
#define encrypt(byte_in, byte_out, hmac) \
	shuffle(r_seed); /* Perform XORSHIFT on the PRNG seed */\
	byte_out = (byte_in & 0xFF) ^ (r_seed & 0xFF); /* XOR's the byte with the first 8 bits of the PRNG seed */\
	calcHash(byte_in, hmac, counter); /* Calculates the HMAC of the plaintext byte */\
	r_seed ^= hmac /* Mix the current HMAC with the seed, making the seed change with the data */

/* Decrypts a single byte, adjusting the HMAC accordingly
 */
#define decrypt(byte_in, byte_out, hmac) \
	shuffle(r_seed); /* Perform XORSHIFT on the PRNG seed */\
	byte_out = (byte_in & 0xFF) ^ (r_seed & 0xFF); /* XOR's the byte with the first 8 bits of the PRNG seed */\
	calcHash(byte_in & 0xFF, hmac, counter); /* Calculates the HMAC of the plaintext byte */\
	r_seed ^= hmac /* Mix the current HMAC with the seed, making the seed change with the data */

/* Initializes common variables used when encrypting/decrypting
 */
#define head(key) \
	keyType ipad = (key) ^ IPAD; \
	keyType opad = (key) ^ OPAD; \
	keyType hmac = ipad; \
	int counter = 0; /* This specifies the number of bits to lshift the hash byte by. Increments by 1 and rolls over after sizeof(keyType)*8-8 */ \
	shuffle(hmac); \
	r_seed = ( key > 1 ? key : 1)

/* Finalizes the HMAC
 */
#define tail() \
	hmac ^= opad; \
	shuffle(hmac)

/*
	HMAC is appended to the end of the stream. it is a specialized checksum of the contents.
	it will change according to the contents, AND the given key
	additionally, the HMAC is calculated with encryption/decryption, and is the same size as the PRNG seed
	this means the PRNG seed can be xor'd with the current HMAC, which means changing one bit changes the entire rest of the message

*/

void fencrypt(FILE* input, FILE* output, keyType key, unsigned long size, const char* IV, unsigned long IVsize)
{
	head(key); // Init variables
	// thisByte/outByte are both used when dealing with file encryption/decryption
	int thisByte;
	char outByte;
	unsigned long i = 0;

	// Bring in the IV first
	while (i++ < IVsize)
	{
		encrypt(IV[i], outByte, hmac);
		fputc(outByte, output);
	}

	i = 0;
	while (i++ < size-sizeof(keyType) && (thisByte = fgetc(input)) != EOF) // Run through each byte
	{
		encrypt(thisByte, outByte, hmac);
		fputc(outByte, output); // Places the encrypted text into the output
	}
	tail(); // Finalizes HMAC
	fwrite((void*)&hmac, sizeof(keyType), 1, output); // Append the HMAC to the output
}

int fdecrypt(FILE* input, FILE* output, keyType key, unsigned long size, unsigned long IVsize)
{
	if (size < sizeof(keyType)) return 0;
	keyType givenHMAC; // Declaring this so we can compare the embedded HMAC with the one we calculated
	head(key); // Init vars
	// thisByte/outByte are both used when dealing with file encryption/decryption
	int thisByte;
	char outByte;
	unsigned long i = 0;
	
	// Deal with the IV first. We can simply discard its contents
	while (i++ < IVsize && (thisByte = fgetc(input)) != EOF)
	{
		decrypt(thisByte, outByte, hmac);
		// IV is garbage data, so don't use it anymore
	}

	i = 0;
	while (i++ < size-sizeof(keyType)-IVsize && (thisByte = fgetc(input)) != EOF) // Increase iterator; if we're still in range, read a character
	{
		decrypt(thisByte, outByte, hmac);
		fputc(outByte, output);
	}
	tail(); // Finalizes HMAC
	fread((void*)&givenHMAC, sizeof(keyType), 1, input); // Reads the HMAC from the message
	return givenHMAC == hmac; // Check validity of HMAC.

}

void sencrypt(const char* input, char* output, keyType key, unsigned long size, const char* IV, unsigned long IVsize)
{

	head(key); // Init vars
	unsigned long i;

	for (i = 0; i < IVsize; i++)
	{
		encrypt(IV[i], output[i], hmac);
	}

	for (i = 0; i < size; i++)
	{
		encrypt(input[i], output[i + IVsize], hmac);
	}
	tail();
	*( (keyType*)( output + IVsize + size ) ) = hmac; // This essentially writes the HMAC to the last bit of the output buffer. It's scary, but that's what it does
	
}

int sdecrypt(const char* input, char* output, keyType key, unsigned long size, unsigned long IVsize)
{
	if (size < sizeof(keyType)) return 0;

	head(key);
	keyType givenHMAC;
	unsigned long i;
	char unusedByte;

	for (i = 0; i < IVsize; i++)
	{
		decrypt(input[i], unusedByte, hmac);
	}

	for (i = 0; i < size-sizeof(keyType)-IVsize; i++)
	{
		decrypt(input[i+IVsize], output[i], hmac);
	}
	tail();
	givenHMAC = *( (keyType*)( input + size - sizeof(keyType) ) ); // This fetches the HMAC from the input buffer and into givenHMAC
	return givenHMAC == hmac;

}

