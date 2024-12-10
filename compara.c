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

//Le um arquivo de entrada de 16 em 16 bytes, encriptando com a função aes_cipher e escrevendo no arquivo de saída
void encrypt_modified_AES(FILE* input, FILE* output, uint8_t *w, int key_size) {

	uint8_t in[16];
	uint8_t out[16];
	int Nr = 0;

	switch(key_size / 8)
	{
	case 16: Nr = 10; break;
	case 24: Nr = 12; break;
	case 32: Nr = 14; break;
	default:
	}

	unsigned char count;
	while ((count = fread(&in, 1, 16, input)) == 16) {
		aes_cipher(in, out, w, Nr);
		fwrite(out, 1, 16, output);
	}

	for(unsigned char i = count; i < 16; i++) {
		in[i] = 88;
	}

	aes_cipher(in, out, w, Nr);
	fwrite(out, 1, 16, output);

}

//Semelhante a função de encriptação;
void decrypt_modified_AES(FILE* input, FILE* output, uint8_t *w, int key_size) {

	uint8_t in[16];
	uint8_t out[16];
	int Nr;	
	
	switch(key_size / 8)
	{
	case 16: Nr = 10; break;
	case 24: Nr = 12; break;
	case 32: Nr = 14; break;
	default:
	}

	while (fread(&in, 1, 16, input) == 16) {
		aes_inv_cipher(in, out, w, Nr);
		fwrite(out, 1, 16, output);
	}

}

//Le o buffer "plaintext" e encripta com a biblioteca o OpenSSL, retorna a saida critografada em "ciphertext"
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

//Semelhante a função de encriptação;
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
				key_size = atoi(optarg);
				break;
			case 'i':
				input_file_name = optarg;
				break;
			default:
				break;
		}
	}
	
	if(key_file_name == NULL || input_file_name == NULL || (key_size != 128 && key_size != 192 && key_size != 256))
	{
		printf("Usage: -k <key_file> -s <key_size> -i <input_file>\n");
		return 1;
	}

	printf("key_file: %s key_size: %d input_file: %s\n\n", 
	key_file_name, key_size, input_file_name);

	FILE* input = fopen(input_file_name, "rb");
	FILE* key_file = fopen(key_file_name, "rb");

//++++++++++++++++++ TROCA-CAIXA ++++++++++++++++++++++++
// SETUP
	uint8_t key_m[key_size / 8];
	fread(&key_m, 1, key_size / 8, key_file);

	uint8_t *w = aes_init(sizeof(key_m));
	aes_key_expansion(key_m, key_size, w);

// ENCRYPT
	FILE* ecrpt_modificado = fopen("saidas/encriptado_A", "wb+");

	printf("Encriptando com AES modificado....\n");
	tempo = clock();
	encrypt_modified_AES(input, ecrpt_modificado, w, key_size); //Encripta.
	tempo = clock() - tempo;
	printf("Tempo: %f\n", ((double)tempo)/CLOCKS_PER_SEC);

	rewind(ecrpt_modificado);

// DECRYPT
	FILE* dcrpt_modificado = fopen("saidas/decriptado_A", "wb");

	printf("Decriptando com AES modificado....\n");
	tempo = clock();
	decrypt_modified_AES(ecrpt_modificado, dcrpt_modificado, w, key_size);
	tempo = clock() - tempo;
	printf("Tempo: %f\n", ((double)tempo)/CLOCKS_PER_SEC);

	fclose(dcrpt_modificado);
	fclose(ecrpt_modificado);


//++++++++++++++++++ OPEN-SSL ++++++++++++++++++++++++
// SETUP

	uint8_t key_o[key_size / 8];
	uint8_t iv[AES_BLOCK_SIZE];

	RAND_bytes(key_o, sizeof(key_o));
	RAND_bytes(iv, sizeof(iv));

	fseek(input, 0, SEEK_END);
    long input_size = ftell(input); //Le o tamanho da entrada.
    rewind(input);
	
	unsigned char *plaintext = malloc(input_size);
    fread(plaintext, 1, input_size, input); //Passa para o buffer.
    fclose(input);
	
// ENCRYPT
	unsigned char *ciphertext = malloc(input_size + AES_BLOCK_SIZE);
	//Buffer para o texto encriptado.

	printf("\nEncriptando com OpenSSL....\n");
	tempo = clock();
    int ciphertext_len = encrypt_Openssl(plaintext, input_size, key_o, iv, ciphertext);
	tempo = clock() - tempo;
	printf("Tempo: %f\n", ((double)tempo)/CLOCKS_PER_SEC);

	//Escreve a saída no arquivo.
	FILE* ecrpt_Openssl = fopen("saidas/encriptado_B", "wb+");
	fwrite(ciphertext, 1, ciphertext_len, ecrpt_Openssl);
	fclose(ecrpt_Openssl);
	

// DECRIPT
	unsigned char *decryptedtext = malloc(ciphertext_len); 
	//Buffer para o texto decriptado.
	
	printf("Decriptando com OpenSSL....\n");
	tempo = clock();
    int decryptedtext_len = decrypt_Openssl(ciphertext, ciphertext_len, key_o, iv, decryptedtext); 
	tempo = clock() - tempo;
	printf("Tempo: %f\n", ((double)tempo)/CLOCKS_PER_SEC);
	
	decryptedtext[decryptedtext_len] = '\0';
	
	//Escreve a saída no arquivo.
	FILE* dcrpt_Openssl = fopen("saidas/decriptado_B", "wb");
	fwrite(decryptedtext, 1, decryptedtext_len, dcrpt_Openssl);
	fclose(dcrpt_Openssl);
	
	return 0;

}
