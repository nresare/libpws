/* Copyright © 2011 Noa Resare */

#include "sph_sha2.h"

/*
 * Implements the hmac algorithm as described in RFC2104 using SHA256 as hashing algorithm.
 */

typedef struct hmac_state {
    sph_sha256_context inner;
    sph_sha256_context outer;
} hmac_state;


void hmac_init(hmac_state *state, unsigned char *key, int key_length);

void hmac_update(hmac_state *state, unsigned char *data, int count);

void hmac_result(hmac_state *state, unsigned char *target);