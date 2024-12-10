/*
 * Advanced Encryption Standard
 * @author Dani Huertas
 * @email huertas.dani@gmail.com
 *
 * Based on the document FIPS PUB 197
 */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <time.h>
#include "aes.h"

#define AES_BLOCK_SIZE 16

void encrypt_modified_AES(FILE* input, FILE* output, uint8_t *w) {

	uint8_t in[16];
	uint8_t out[16];
	
	unsigned char count;
	while ((count = fread(&in, 1, 16, input)) == 16) {
		aes_cipher(in, out, w);
		fwrite(out, 1, 16, output);
	}
	
	//unsigned char rest = 16 - count;
	//printf("remain: %d\n", rest);

	for(unsigned char i = count; i < 16; i++) {
		in[i] = 88;
	}

	aes_cipher(in, out, w);
	fwrite(out, 1, 16, output);

}

void decrypt_modified_AES(FILE* input, FILE* output, uint8_t *w) {

	uint8_t in[16];
	uint8_t out[16];
	
	while (fread(&in, 1, 16, input) == 16) {
		aes_inv_cipher(in, out, w);
		fwrite(out, 1, 16, output);
	}

}

int encrypt_Openssl(const unsigned char *plaintext, int plaintext_len, const unsigned char *key,
            const unsigned char *iv, unsigned char *ciphertext) {
    
    EVP_CIPHER_CTX *ctx;
    
    int len, ciphertext_len;

    ctx = EVP_CIPHER_CTX_new();
    
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);

    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int decrypt_Openssl(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key,
            const unsigned char *iv, unsigned char *plaintext) {
    
    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len;

    ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);

    plaintext_len = len;

    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int main(int argc, char *argv[]) {

	char *key_file_name, *input_file_name;
	int key_size;
	int opt;
	clock_t tempo;
	while ((opt = getopt(argc, argv, "k:s:i:o:")) != -1)
	{
		switch (opt)
		{
			case 'k':
				key_file_name = optarg;
				break;
			case 's':
				key_size = atoi(optarg) / 8;
				break;
			case 'i':
				input_file_name = optarg;
				break;
			default:
				break;
		}
	}
	
	printf("key_file: %s key_size: %d input_file: %s\n\n", key_file_name, key_size, input_file_name);

	FILE* input = fopen(input_file_name, "rb");
	FILE* key_file = fopen(key_file_name, "rb");

	uint8_t key_m[key_size / 8];
	uint8_t key_o[key_size / 8];

	uint8_t iv[AES_BLOCK_SIZE];
	uint8_t *w;
	
	fread(&key_m, 1, key_size, key_file);
	
	w = aes_init(sizeof(key_m));
	
	aes_key_expansion(key_m, w);

	if (!RAND_bytes(key_o, sizeof(key_o)) || !RAND_bytes(iv, sizeof(iv))) {
        fprintf(stderr, "Erro ao gerar chave ou IV\n");
        return 1;
    }
	
//+++++++++++++++++= ENCRIPTANDO ++++================
	
	printf("Encriptando:\n");

	FILE* ecrpt_modificado = fopen("encriptado_A", "wb+");
	tempo = clock();
	encrypt_modified_AES(input, ecrpt_modificado, w);
	tempo = clock() - tempo;
	printf("Tempo do AES modificado: %f\n", ((double)tempo)/CLOCKS_PER_SEC);

	fseek(input, 0, SEEK_END);
    long input_size = ftell(input);
    rewind(input);
	
	unsigned char *plaintext = malloc(input_size);
    fread(plaintext, 1, input_size, input);
    fclose(input);
	
	unsigned char *ciphertext = malloc(input_size + AES_BLOCK_SIZE);
	tempo = clock();
    int ciphertext_len = encrypt_Openssl(plaintext, input_size, key_o, iv, ciphertext);
	tempo = clock() - tempo;
	printf("Tempo do OpenSSL: %f\n", ((double)tempo)/CLOCKS_PER_SEC);

	FILE* ecrpt_Openssl = fopen("encriptado_B", "wb+");
	fwrite(ciphertext, 1, ciphertext_len, ecrpt_Openssl);
	fclose(ecrpt_Openssl);

	rewind(ecrpt_modificado);
	rewind(ecrpt_Openssl);

//+++++++++++++++++= DECRIPTANDO ++++================
	
	printf("\nDecriptando:\n");

	FILE* dcrpt_modificado = fopen("decriptado_A", "wb");
	tempo = clock();
	decrypt_modified_AES(ecrpt_modificado, dcrpt_modificado, w);
	tempo = clock() - tempo;
	printf("Tempo do AES modificado: %f\n", ((double)tempo)/CLOCKS_PER_SEC);
	fclose(dcrpt_modificado);
	fclose(ecrpt_modificado);

	unsigned char *decryptedtext = malloc(ciphertext_len);
	tempo = clock();
    int decryptedtext_len = decrypt_Openssl(ciphertext, ciphertext_len, key_o, iv, decryptedtext);
	tempo = clock() - tempo;
	printf("Tempo do OpenSSL: %f\n", ((double)tempo)/CLOCKS_PER_SEC);
	decryptedtext[decryptedtext_len] = '\0';
	
	FILE* dcrpt_Openssl = fopen("decriptado_B", "wb");
	fwrite(decryptedtext, 1, decryptedtext_len, dcrpt_Openssl);
	fclose(dcrpt_Openssl);
	
	return 0;

}
