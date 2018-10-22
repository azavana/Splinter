#ifndef __Header_h
#define __Header_h

#include <openssl/sha.h>

int GCD (int a, int b);

long int bin (int x);

void swap (unsigned char *a, unsigned char  *b);

unsigned char *swap_character (unsigned char *text);

void KSA (char *key, unsigned char S[256]);

void RC4A_PRG (unsigned char S1[256], unsigned char S2[256], unsigned char *plaintext, unsigned char *ciphertext);

void RC4A_Encrypt (unsigned char *plaintext, unsigned char *ciphertext, char *key);

void Spritz_PRG (unsigned char S[256], unsigned char *plaintext, unsigned char *ciphertext);

void Spritz_Encrypt (unsigned char *plaintext, unsigned char *ciphertext, char *key);

void RC4A_SPRITZ_PRG (unsigned char S1[256], unsigned char S2[256], unsigned char *plaintext, unsigned char *ciphertext);

void RC4A_Spritz_Encrypt (unsigned char *plaintext, unsigned char *ciphertext, char *key);

unsigned char *RC4A_Key();

unsigned char *Spritz_Key();

unsigned char *RC4A_Spritz_Key();

char *Salt();

void SHA_256 (unsigned char *text);

void SHA_384 (unsigned char *text);

void SHA_512 (unsigned char *text);

void RMD_160 (unsigned char *text);

#endif

