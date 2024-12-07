/*
 * Advanced Encryption Standard
 * @author Dani Huertas
 * @email huertas.dani@gmail.com
 *
 * Based on the document FIPS PUB 197
 */
#include <stdio.h>

#include "aes.h"

int main() {

	FILE* input = fopen("input.txt", "rb");
	FILE* key_file = fopen("key.txt", "rb");
	FILE* cript = fopen("cript", "wb+");
	FILE* output = fopen("output.txt", "wb");

	uint8_t key[16];
	uint8_t in[16];
	uint8_t out[16];
	uint8_t *w;
	
	fread(&key, 1, 16, key_file);

	for(int i = 0; i < 16; i++) {
		printf("%x ", key[i]);
	} printf("\n");
	
	w = aes_init(sizeof(key));

	aes_key_expansion(key, w);
	
	unsigned char count;
	while ((count = fread(&in, 1, 16, input)) == 16) {
		aes_cipher(in, out, w);
		fwrite(out, 1, 16, cript);
	}
	unsigned char rest = 16 - count;
	printf("remain: %d\n", 16 - rest);

	for(unsigned char i = count; i < 16; i++) {
		in[i] = rest;
	}
	
	aes_cipher(in, out, w);
	fwrite(out, 1, 16, cript);
	


	rewind(cript);

	while (fread(&in, 1, 16, cript) == 16) {
		aes_inv_cipher(in, out, w);
		fwrite(out, 1, 16, output);
	}
	return 0;
}
