// Contains all functions used in the programs

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <string.h>
#include <math.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

// Usefull in Spritz
int GCD (int a, int b)
{
	if (a > b) {
		if (a%b == 0)
			return b;
		else
			return GCD (b, a%b);
	}
	else {
		if (b%a == 0)
			return a;
		else
			return GCD (a, b%a);
	}
}

// Used in RC4A and Spritz
void swap (unsigned char *a, unsigned char *b)
{
	int tmp = *a;
	*a = *b;
	*b = tmp;
}

// Used to swap the character before performing any encryption
unsigned char *swap_character (unsigned char *text)
{
	unsigned char *result = malloc(sizeof(unsigned char) * strlen(text));
	assert (result != NULL);
	int len = strlen(text);

	if (len % 2 == 0)
	{
		for (int i = 0; i < len; i++) {
			swap (&text[i], &text[i+1]);			
			result[i] = text[i];
			result[i+1] = text[i+1];
		}
	}
	else
	{
		for (int i = 0; i < len-1; i++) {
			swap (&text[i], &text[i+1]);
			result[i] = text[i];
			result[i+1] = text[i+1];
		}
		result[len-1] = text[len-1];
	}
	return result;
}

void KSA (char *key, unsigned char S[256])
{
	for (int i = 0; i < 256; i++)
		S[i] = i;

	int j = 0;

	for (int i = 0; i < 256; i++)
	{
		j = (j + S[i] + key[i % strlen(key)]) % 256;
		swap (&S[i], &S[j]);
	}
	return;
}

void RC4A_PRG (unsigned char S1[256], unsigned char S2[256], unsigned char *plaintext, unsigned char *ciphertext)
{
	int i = 0;
	int j1 = 0, j2 = 0;

	for (int n = 0; n < strlen(plaintext); n++)
	{
		i = (i + 1) % 256;
		
		j1 = (j1 + S1[i]) % 256;
		swap (&S1[i], &S1[j1]);
		int K1 = S2[(S1[i] + S1[j1]) % 256];

		ciphertext[n] = K1^plaintext[n];
	}

	for (int k = 0; k < strlen(ciphertext); k++)
	{
		i = (i + 1) % 256;
		
		j2 = (j2 + S2[i]) % 256;
		swap (&S2[i], &S2[j2]);
		int K2 = S1[(S2[i] + S2[j2]) % 256];

		ciphertext[k] = K2^plaintext[k];
	}

	return;
}

void RC4A_Encrypt (unsigned char *plaintext, unsigned char *ciphertext, char *key)
{
	unsigned char S1[256];
	unsigned char S2[256];

	KSA (key, S1);
	KSA (key, S2);

	RC4A_PRG (S1, S2, plaintext, ciphertext);

	return;
}

// Generate the RC4A key randomly
unsigned char *RC4A_Key()
{
	srand(time(NULL));
	int len_key = rand() % 256 + 5; // RC4A key length is between 40 bits to 2048 bits
	int key, random;

	unsigned char *key_stream = malloc(sizeof(unsigned char) * len_key);
	assert (key_stream != NULL);

	for (int i = 0; i < len_key; i++)
	{
		random = rand() % 2;
		key = rand() % 26;
		if (random == 0)
			key_stream[i] = (char)((key-65) % 26 + 65);
		else
			key_stream[i] = (char)((key-97) % 26 + 97);
	}
	return key_stream;
}


// Spritz PRG
void Spritz_PRG (unsigned char S[256], unsigned char *plaintext, unsigned char *ciphertext)
{
	int i = 0, j = 0, k = 0, w =0;
	
	for (int n = 0; n < strlen(plaintext); n++)
	{
		do
			w = rand() % 256 + 1;
		while (GCD (w, 256) != 1);
		
		i = (i + w) % 256;
		j = (k + S[j] + S[i]) % 256;
		k = (k + i + S[j]) % 256;

		swap (&S[i], &S[j]);

		int z = S[(j + S[i + S[z + k]]) % 256];

		ciphertext[n] = z^plaintext[n];
	}
	return;
}

void Spritz_Encrypt (unsigned char *plaintext, unsigned char *ciphertext, char *key)
{
	unsigned char S[256];

	KSA (key, S);

	Spritz_PRG (S, plaintext, ciphertext);

	return;
}

// Generate Spritz key randomly	
unsigned char *Spritz_Key()
{
	srand(time(NULL));
	int len_key = rand() % 256 + 5; // Spritz key length is between 40 bits to 2048 bits
	int key, random;

	unsigned char *key_stream = malloc(sizeof(unsigned char) * len_key);
	assert (key_stream != NULL);

	for (int i = 0; i < len_key; i++)
	{
		random = rand() % 2;
		key = rand() % 26;
		if (random == 0)
			key_stream[i] = (char)((key-65) % 26 + 65);
		else
			key_stream[i] = (char)((key-97) % 26 + 97);
	}
	return key_stream;
}

// RC4A_SPRITZ is a combination of RC4A and SPRITZ; two of updated version of RC4
void RC4A_SPRITZ_PRG (unsigned char S1[256], unsigned char S2[256], unsigned char *plaintext, unsigned char *ciphertext)
{
	int i = 0;
	int j1 = 0, j2 = 0;
	int k1 = 0, k2 = 0;
	int w1 = 0, w2 = 0;
	int z1 = 0, z2 = 0;

	srand(time(NULL));

	for (int n = 0; n < strlen(plaintext); n++)
	{
		do
		{
			w1 = rand() % 256 + 1; // w1 is relatively prime to S1 size; 256
		} while (GCD(w1,256) != 1);

		i = (i + w1) % 256;
		j1 = (k1 + S1[j1] + S1[i]) % 256;
		k1 = (k1 + i + S1[j1]) % 256;
		swap (&S1[i], &S1[j1]);
		z1 = S2[(j1 + S1[i + S1[z1 + k1]]) % 256];

		ciphertext[n] = z1^plaintext[n];
	}
	
	for (int k = 0; k < strlen(ciphertext); k++)
	{
		do
		{
			w2 = rand() % 256 + 1; // w2 is relatively prime to S2 size; 256
		} while (GCD(w2,256) != 1);

		i = (i + w2) % 256;
		j2 = (k2 + S2[j2] + S2[i]) % 256;
		k2 = (k2 + i + S2[j2]) % 256;
		swap (&S2[i], &S2[j2]);
		z2 = S1[(j2 + S2[i + S2[z2 + k2]]) % 256];

		ciphertext[k] = z2^ciphertext[k];
	}
	return;
}

// RC4A_Spritz Encrypt function
void RC4A_Spritz_Encrypt (unsigned char *plaintext, unsigned char *ciphertext, char *key)
{
	unsigned char S1[256];
	unsigned char S2[256];

	KSA (key, S1);
	KSA (key, S2);

	RC4A_SPRITZ_PRG (S1, S2, plaintext, ciphertext);

	return;
}

// RC4A_Spritz Key
unsigned char *RC4A_Spritz_Key() 
{
	srand(time(NULL));
	int len = rand() % 256 + 5; // Key length between 5 Bytes (40 bits) and 256 Bytes (2048 bits)
	unsigned char *Key = malloc(sizeof(unsigned char) * len);
	assert (Key != NULL);

	for (int i = 0; i < len; i++)
	{
		int random = rand() % 2;
		int key = rand() % 26;
		if (random == 0)
			Key[i] = (char)((key-65) % 26 + 65);
		else if (random == 1)
			Key[i] = (char)((key-97) % 26 + 97);
	}
	return Key;
}

// Salt the clear message
char *Salt()
{
	
	unsigned char *string = malloc(sizeof(unsigned char) * 8);
	assert (string != NULL);
	srand(time(NULL));
	int i = 0;

	while (i < 8)
	{
		int random = rand() % 2;
		int key = rand() % 26;

		if (random == 0)
			string[i] = (char)((key-65) % 26 + 65);
		else if (random == 1)
			string[i] = (char)((key-97) % 26 + 97);
		i += 1;
	}
	return string;
}

void SHA_256 (unsigned char *text)
{
	unsigned char digest_256[SHA256_DIGEST_LENGTH];
	SHA256 (text, strlen(text), digest_256);

	for (int x = 0; x < SHA256_DIGEST_LENGTH; x++)
		printf("%02o", digest_256[x]); 
	
	return;
}

void SHA_384 (unsigned char *text)
{
	unsigned char digest_384[SHA384_DIGEST_LENGTH];
	SHA384 (text, strlen(text), digest_384);

	for (int x = 0; x < SHA384_DIGEST_LENGTH; x++)
		printf("%02o", digest_384[x]);

	return;
}

void SHA_512 (unsigned char *text)
{
	unsigned char digest_512[SHA512_DIGEST_LENGTH];
	SHA512 (text, strlen(text), digest_512);

	for (int x = 0; x < SHA512_DIGEST_LENGTH; x++)
		printf("%02o", digest_512[x]);

	return;
}

void RMD_160 (unsigned char *text)
{
	unsigned char RMD_Digest[RIPEMD160_DIGEST_LENGTH];
	RIPEMD160 (text, strlen(text), RMD_Digest);

	for (int x = 0; x < RIPEMD160_DIGEST_LENGTH; x++)
		printf("%02o", RMD_Digest[x]);

	return;
}

