
#include <stdio.h>
#include "vigenere.h"

void vigenere(uint8_t *state, uint8_t *w, uint8_t r) {
		
	uint8_t c;
	
	for (c = 0; c < 16; c++) {
		state[c] = (state[c] + w[c]) % 256;
	}

}

void inv_vigenere(uint8_t *state, uint8_t *w, uint8_t r) {
		
	uint8_t c;

	for (c = 0; c < 16; c++) {
		state[c] = (state[c] - w[c]) % 256;
	}

}