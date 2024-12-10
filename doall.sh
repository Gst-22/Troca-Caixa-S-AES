gcc aes.c compara.c -o aes -lcrypto -lssl

./aes -k key.txt -s 256 -i input.txt -o encriptado.txt