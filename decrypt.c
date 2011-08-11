/* Copyright © 2011 Noa Resare */

#include <string.h>

#include "decrypt.h"
#include "twofish.h"

void decrypt_setup(cbc_state *dec, unsigned char *key, unsigned char *iv)
{
    Twofish_initialise();
    Twofish_prepare_key(key, 32, &dec->twokey);
    memcpy(dec->cbc_state, iv, 16);
}

void decrypt_cbc(cbc_state *dec, unsigned char *in, unsigned char *target)
{
    unsigned int i;
    Twofish_decrypt(&dec->twokey, in, target);
    for (i = 0; i < 16; i++) {
        target[i] = target[i] ^ dec->cbc_state[i];
        dec->cbc_state[i] = in[i];
    }
}

void decrypt_twofish_ecb_32(unsigned char *key, unsigned char *buf, unsigned char *result)
{
    Twofish_key twokey;
    Twofish_initialise();
    Twofish_prepare_key(key, 32, &twokey);
    Twofish_decrypt(&twokey, buf, result);
    Twofish_decrypt(&twokey, buf + 16, result + 16);
}
