/*
 * Advanced Encryption Standard
 * @author Dani Huertas
 * @email huertas.dani@gmail.com
 *
 * Based on the document FIPS PUB 197
 */

#include <stdio.h>
#include "aes.h"

#define NB 4

static uint8_t s_box[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

uint8_t gmult(uint8_t a, uint8_t b) {

	uint8_t p = 0, i = 0, hbs = 0;

	for (i = 0; i < 8; i++) {
		if (b & 1) {
			p ^= a;
		}

		hbs = a & 0x80;
		a <<= 1;
		if (hbs) a ^= 0x1b;	
		b >>= 1;
	}

	return (uint8_t)p;
}

void vigenere(uint8_t *state, uint8_t *w, uint8_t r) {
	for (uint8_t i = 0; i < 16; i++) {
		state[i] = (state[i] + w[i]) % 256;
	}
}

void inv_vigenere(uint8_t *state, uint8_t *w, uint8_t r) {
	for (uint8_t i = 0; i < 16; i++) {
		state[i] = (state[i] - w[i]) % 256;
	}
}

void coef_add(uint8_t a[], uint8_t b[], uint8_t d[]) {

	d[0] = a[0]^b[0];
	d[1] = a[1]^b[1];
	d[2] = a[2]^b[2];
	d[3] = a[3]^b[3];
}

void coef_mult(uint8_t *a, uint8_t *b, uint8_t *d) {

	d[0] = gmult(a[0],b[0])^gmult(a[3],b[1])^gmult(a[2],b[2])^gmult(a[1],b[3]);
	d[1] = gmult(a[1],b[0])^gmult(a[0],b[1])^gmult(a[3],b[2])^gmult(a[2],b[3]);
	d[2] = gmult(a[2],b[0])^gmult(a[1],b[1])^gmult(a[0],b[2])^gmult(a[3],b[3]);
	d[3] = gmult(a[3],b[0])^gmult(a[2],b[1])^gmult(a[1],b[2])^gmult(a[0],b[3]);
}

/*
 * Generates the round constant Rcon[i]
 */
uint8_t R[] = {0x02, 0x00, 0x00, 0x00};

uint8_t * Rcon(uint8_t i) {
	
	if (i == 1) {
		R[0] = 0x01; // x^(1-1) = x^0 = 1
	} else if (i > 1) {
		R[0] = 0x02;
		i--;
		while (i > 1) {
			R[0] = gmult(R[0], 0x02);
			i--;
		}
	}
	
	return R;
}

void add_round_key(uint8_t *state, uint8_t *w, uint8_t r) {
	
	uint8_t c;
	
	for (c = 0; c < NB; c++) {
		state[NB*0+c] = state[NB*0+c]^w[4*NB*r+4*c+0];
		state[NB*1+c] = state[NB*1+c]^w[4*NB*r+4*c+1];
		state[NB*2+c] = state[NB*2+c]^w[4*NB*r+4*c+2];
		state[NB*3+c] = state[NB*3+c]^w[4*NB*r+4*c+3];	
	}
}

void mix_columns(uint8_t *state) {

	uint8_t a[] = {0x02, 0x01, 0x01, 0x03};
	uint8_t i, j, col[4], res[4];

	for (j = 0; j < NB; j++) {
		for (i = 0; i < 4; i++) {
			col[i] = state[NB*i+j];
		}

		coef_mult(a, col, res);

		for (i = 0; i < 4; i++) {
			state[NB*i+j] = res[i];
		}
	}
}

void inv_mix_columns(uint8_t *state) {

	uint8_t a[] = {0x0e, 0x09, 0x0d, 0x0b};
	uint8_t i, j, col[4], res[4];

	for (j = 0; j < NB; j++) {
		for (i = 0; i < 4; i++) {
			col[i] = state[NB*i+j];
		}

		coef_mult(a, col, res);

		for (i = 0; i < 4; i++) {
			state[NB*i+j] = res[i];
		}
	}
}

void shift_rows(uint8_t *state) {

	uint8_t i, k, s, tmp;

	for (i = 1; i < 4; i++) {
		// shift(1,4)=1; shift(2,4)=2; shift(3,4)=3
		// shift(r, 4) = r;
		s = 0;
		while (s < i) {
			tmp = state[NB*i+0];
			
			for (k = 1; k < NB; k++) {
				state[NB*i+k-1] = state[NB*i+k];
			}

			state[NB*i+NB-1] = tmp;
			s++;
		}
	}
}

void inv_shift_rows(uint8_t *state) {

	uint8_t i, k, s, tmp;

	for (i = 1; i < 4; i++) {
		s = 0;
		while (s < i) {
			tmp = state[NB*i+NB-1];
			
			for (k = NB-1; k > 0; k--) {
				state[NB*i+k] = state[NB*i+k-1];
			}

			state[NB*i+0] = tmp;
			s++;
		}
	}
}

void sub_bytes(uint8_t *state) {

	uint8_t i, j;
	
	for (i = 0; i < 4; i++) {
		for (j = 0; j < NB; j++) {
			// s_box row: yyyy ----
			// s_box col: ---- xxxx
			// s_box[16*(yyyy) + xxxx] == s_box[yyyyxxxx]
			state[NB*i+j] = s_box[state[NB*i+j]];
		}
	}
}

void sub_word(uint8_t *w) {

	uint8_t i;

	for (i = 0; i < 4; i++) {
		w[i] = s_box[w[i]];
	}
}

void rot_word(uint8_t *w) {

	uint8_t tmp;
	uint8_t i;

	tmp = w[0];

	for (i = 0; i < 3; i++) {
		w[i] = w[i+1];
	}

	w[3] = tmp;
}

void aes_key_expansion(uint8_t *key, int key_size, uint8_t *w) {
	
	int Nr, Nk;	
	switch(key_size / 8)
	{
	case 16: Nk = 4; Nr = 10; break;
	case 24: Nk = 6; Nr = 12; break;
	case 32: Nk = 8; Nr = 14; break;
	default:
	}
	
	uint8_t tmp[4];
	uint8_t i;
	uint8_t len = NB*(Nr+1);

	for (i = 0; i < Nk; i++) {
		w[4*i+0] = key[4*i+0];
		w[4*i+1] = key[4*i+1];
		w[4*i+2] = key[4*i+2];
		w[4*i+3] = key[4*i+3];
	}

	for (i = Nk; i < len; i++) {
		tmp[0] = w[4*(i-1)+0];
		tmp[1] = w[4*(i-1)+1];
		tmp[2] = w[4*(i-1)+2];
		tmp[3] = w[4*(i-1)+3];

		if (i%Nk == 0) {

			rot_word(tmp);
			sub_word(tmp);
			coef_add(tmp, Rcon(i/Nk), tmp);

		} else if (Nk > 6 && i%Nk == 4) {

			sub_word(tmp);

		}

		w[4*i+0] = w[4*(i-Nk)+0]^tmp[0];
		w[4*i+1] = w[4*(i-Nk)+1]^tmp[1];
		w[4*i+2] = w[4*(i-Nk)+2]^tmp[2];
		w[4*i+3] = w[4*(i-Nk)+3]^tmp[3];
	}
}

uint8_t *aes_init(size_t key_size) {
    int Nr, Nk;
		switch (key_size) {
		default:
		case 16: Nk = 4; Nr = 10; break;
		case 24: Nk = 6; Nr = 12; break;
		case 32: Nk = 8; Nr = 14; break;
	}

	return malloc(Nk * (Nr + 1)*4);
}

void aes_cipher(uint8_t *in, uint8_t *out, uint8_t *w, int Nr) {

	uint8_t state[4*NB];
	uint8_t r, i, j;

	for (i = 0; i < 4; i++) {
		for (j = 0; j < NB; j++) {
			state[NB*i+j] = in[i+4*j];
		}
	}

	add_round_key(state, w, 0);

	for (r = 1; r < Nr; r++) {
		vigenere(state, w, r);
		shift_rows(state);
		mix_columns(state);
		add_round_key(state, w, r);
	}

	vigenere(state, w, Nr);
	shift_rows(state);
	add_round_key(state, w, Nr);

	for (i = 0; i < 4; i++) {
		for (j = 0; j < NB; j++) {
			out[i+4*j] = state[NB*i+j];
		}
	}
}

void aes_inv_cipher(uint8_t *in, uint8_t *out, uint8_t *w, int Nr) {

	uint8_t state[4*NB];
	uint8_t r, i, j;

	for (i = 0; i < 4; i++) {
		for (j = 0; j < NB; j++) {
			state[NB*i+j] = in[i+4*j];
		}
	}

	add_round_key(state, w, Nr);

	for (r = Nr-1; r >= 1; r--) {
		inv_shift_rows(state);
		inv_vigenere(state, w, r);
		add_round_key(state, w, r);
		inv_mix_columns(state);
	}

	inv_shift_rows(state);
	inv_vigenere(state, w, 0);
	add_round_key(state, w, 0);

	for (i = 0; i < 4; i++) {
		for (j = 0; j < NB; j++) {
			out[i+4*j] = state[NB*i+j];
		}
	}
}
