/* Andry Rafam Andrianjafy - October 2018*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <string.h>
#include <openssl/md5.h>
#include "Header.h"

// Main program
int main (int argc, char **argv)
{
	if (argc < 2) {
		printf("\nUsage: %s < Plaintext > \n\n", argv[0]);
		return -1;
	}

	unsigned char *stage0 = malloc(sizeof(unsigned char) * (8 + strlen(argv[1])));
	assert (stage0 != NULL);
	
	strcpy (stage0, argv[1]);
	strcat (stage0, Salt());

	unsigned char *ciphertext = malloc(sizeof(int) * strlen(swap_character(stage0)));
	assert(ciphertext != NULL);	

	printf("\n\n=========== SPLINTER Encryption program ==========\n\n");
	
	// Digital signature of the message
	unsigned char digital_sig[MD5_DIGEST_LENGTH];
	MD5(argv[1], strlen(argv[1]), digital_sig);

	printf("\n[ DIGITAL SIGNATURE ] >> ");
	for (int x = 0; x < MD5_DIGEST_LENGTH; x++)
		printf("%02hhx", digital_sig[x]);
	printf("\n\n"); 

	srand(time(NULL));
	int random = rand() % 7 + 1;

	
	// Perform the encryption
	printf("\n[ ENCRYPTED MESSAGE ] >> ");
	if (random == 1)
	{		
		RC4A_Encrypt (swap_character(stage0), ciphertext, RC4A_Key());
		
		for (int x = 0; x < strlen(swap_character(stage0)); x++)
			printf("%02o%c", ciphertext[x], x < (strlen(swap_character(stage0))-1) ? ' ' : '\n');
		printf("\n\n");
	}
	else if (random == 2) 
	{		
		Spritz_Encrypt (swap_character(stage0), ciphertext, Spritz_Key());
		
		for (int x = 0; x < strlen(swap_character(stage0)); x++)
			printf("%02o%c", ciphertext[x], x < (strlen(swap_character(stage0))-1) ? ' ' : '\n');
		printf("\n\n");
	}
	else if (random == 3)
	{
		RC4A_Spritz_Encrypt (swap_character(stage0), ciphertext, RC4A_Spritz_Key());
		
		for (int x = 0; x < strlen(swap_character(stage0)); x++)
			printf("%02o%c", ciphertext[x], x < (strlen(swap_character(stage0))-1) ? ' ' : '\n');
		printf("\n\n");
	}
	else if (random == 4)
	{		
		SHA_256(swap_character(stage0));
		printf("\n\n");
	}
	else if (random == 5)
	{
		SHA_384(swap_character(stage0));
		printf("\n\n");
	}
	else if (random == 6)
	{
		SHA_512(swap_character(stage0));
		printf("\n\n");
	}
	else if (random == 7)
	{
		RMD_160(swap_character(stage0));
		printf("\n\n");
	}
	
	printf("\n");
	free(stage0);
	free(ciphertext);
	return EXIT_SUCCESS;
}

	
			
