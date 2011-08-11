/* Copyright © 2011 Noa Resare */

#include "twofish.h"

typedef struct cbc_state {
    Twofish_key twokey;
    unsigned char cbc_state[16];
} cbc_state;

void decrypt_setup(cbc_state *state, unsigned char *key, unsigned char *iv);

void decrypt_cbc(cbc_state *dec, unsigned char *in, unsigned char *target);

/** 
 * Reads and descrypts 32 bytes of data using the provided key in ECB mode and writes
 * the resulting data to the buffer referenced by result.
 */
void decrypt_twofish_ecb_32(unsigned char *key, unsigned char *buf, unsigned char *result);