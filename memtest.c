/*

	A tool to test your encryption speed with a 256MiB file

*/

#include "dragoncrypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(int argc, const char* argv[])
{
	if (argc < 3)
	{
		fprintf(stderr, "Usage: %s key(uint64) IVsize(int)\n", argv[0]);
		return 1;
	}
	
	keyType key;
	FILE* input;
	FILE* output;
	clock_t begin;
	clock_t finish;
	long size;
	char* inputData;
	char* outputData;
	int IVsize;
	sscanf(argv[1], "%llu", &key);
	sscanf(argv[2], "%i", &IVsize);

	long testSize = 0x10000000; // 256MiB

	srand(time(0));
	printf("Writing temporary 256MiB file...\n");

	{
		output = fopen("input", "wb");
		for (long i = 0; i < testSize; i++)
		{
			fputc(rand() & 0xFF, output);
		}
		fclose(output);
	}

	double encryptRate, decryptRate;
	{
		printf("Encrypting...");
		char* IV = malloc(sizeof(char) * IVsize);
		for( int i = 0; i < IVsize; i++)
		{
			IV[i] = rand() & 0xFF;
		}
		
		input = fopen("input", "rb");
		fseek(input, 0, SEEK_END);
		size = ftell(input);
		fseek(input, 0, SEEK_SET);

		inputData = malloc(sizeof(char) * size);
		outputData = malloc(sizeof(char) * (size + IVsize) + sizeof(keyType));
		fread((void*)(inputData), sizeof(char), size, input);
		fclose(input);

		begin = clock();
		sencrypt(inputData, outputData, key, size, IV, IVsize);
		finish = clock();
		double duration = (double)((double)(finish-begin)/(double)CLOCKS_PER_SEC);

		double dataRate = (double)testSize / duration; // bytes/sec
		encryptRate = dataRate;

		printf("Done!\nRate: %f mebibytes/s\n", dataRate/1024.0f/1024.0f);

		output = fopen("output", "wb");

		printf("Writing to temporary output file...");
		fwrite((void*)outputData, sizeof(char) * (size + IVsize) + sizeof(keyType), 1, output);

		fclose(output);
		free(inputData);
		free(outputData);
		free(IV);
	}

	remove("input");

	{
		printf("Decrypting...");
		input = fopen("output", "rb");

		fseek(input, 0, SEEK_END);
		size = ftell(input);
		fseek(input, 0, SEEK_SET);

		inputData = malloc(sizeof(char) * size);
		outputData = malloc(sizeof(char) * (size - IVsize) - sizeof(keyType));

		fread((void*)inputData, sizeof(char), size, input);
		fclose(input);

		begin = clock();
		int success = sdecrypt(inputData, outputData, key, size, IVsize);
		char* successStr = success ? "success" : "!!FAILURE!! HMAC did not match";
		finish = clock();

		printf("Done!\nResult: %s\n", successStr);
		double duration = (double)((double)(finish-begin)/(double)CLOCKS_PER_SEC);

		double dataRate = (double)testSize / duration; // bytes/sec
		decryptRate = dataRate;

		printf("Rate: %f mebibytes/s\n", dataRate/1024.0f/1024.0f);

		free(inputData);
		free(outputData);
	}

	remove("output");
	printf("Decryption/Encryption speed: %f%%\n", 100*decryptRate/encryptRate);

	return 0;

}
