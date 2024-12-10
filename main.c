/*
 * Advanced Encryption Standard
 * @author Dani Huertas
 * @email huertas.dani@gmail.com
 *
 * Based on the document FIPS PUB 197
 */
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "aes.h"

void encript_custom(FILE* input, FILE* output, uint8_t *w) {

	uint8_t in[16];
	uint8_t out[16];
	
	unsigned char count;
	while ((count = fread(&in, 1, 16, input)) == 16) {
		aes_cipher(in, out, w);
		fwrite(out, 1, 16, output);
	}
	
	unsigned char rest = 16 - count;
	printf("remain: %d\n", rest);

	for(unsigned char i = count; i < 16; i++) {
		in[i] = 88;
	}

	aes_cipher(in, out, w);
	fwrite(out, 1, 16, output);

}

void decript_custom(FILE* input, FILE* output, uint8_t *w) {

	uint8_t in[16];
	uint8_t out[16];
	
	while (fread(&in, 1, 16, input) == 16) {
		aes_inv_cipher(in, out, w);
		fwrite(out, 1, 16, output);
	}

}

int main(int argc, char *argv[]) {

	char mode; //1 = encript, 0 = decript
	char *key_file_name, *input_file_name, *output_file_name;
	int key_size;
	int opt;
	while ((opt = getopt(argc, argv, "edk:s:i:o:")) != -1)
	{
		switch (opt)
		{
			case 'e':
				mode = 1;
				break;
			case 'd':
				mode = 0;
				break;
			case 'k':
				key_file_name = optarg;
				break;
			case 's':
				key_size = atoi(optarg) / 8;
				break;
			case 'i':
				input_file_name = optarg;
				break;
			case 'o':
				output_file_name = optarg;
				break;
			default:
				break;
		}
	}
	
	printf("mode: %d\nkey_file: %s\n key_size: %d\ninput_file: %s\noutput_file: %s\n", mode, key_file_name, key_size, input_file_name, output_file_name);

	FILE* input = fopen(input_file_name, "rb");
	FILE* key_file = fopen(key_file_name, "rb");
	FILE* cript = fopen(output_file_name, "wb+");
	FILE* output = fopen(output_file_name, "wb");

	uint8_t key[key_size];
	uint8_t *w;
	
	fread(&key, 1, key_size, key_file);

	for(int i = 0; i < key_size; i++) {
		printf("%x ", key[i]);
	} printf("\n");
	
	w = aes_init(sizeof(key));
	
	aes_key_expansion(key, w);
	
	if (mode)
		encript_custom(input, cript, w);
	else
		decript_custom(input, output, w);
	return 0;

}
