/* Copyright © 2011 Noa Resare */

#include <string.h>
#include <openssl/sha.h>

#include "hmac.h"

#ifdef TEST
#include <stdio.h>
#endif

/* block size in bytes of SHA256 */
#define BLOCK_SIZE 64

/* hash output size in bytes for SHA256 */
#define HASH_SIZE 32

/**
 * Initialize the HMAC state stucture 
 */
void hmac_init(hmac_state *state, unsigned char *key, int key_length)
{
    unsigned char tmp[BLOCK_SIZE] = {0};
    int i;

    if (key_length > BLOCK_SIZE) {
        SHA256(tmp, key_length, key);
    } else {
        memcpy(tmp, key, key_length);
    }        

    SHA256_Init(&state->inner);
    SHA256_Init(&state->outer);
    
    for (i = 0; i < BLOCK_SIZE; i++) {
        tmp[i] = tmp[i] ^ 0x36;
        
    }
    SHA256_Update(&state->inner, tmp, BLOCK_SIZE);
    for (i = 0; i < BLOCK_SIZE; i++) {
        tmp[i] = tmp[i] ^ (0x36 ^ 0x5c);

    }
    SHA256_Update(&state->outer, tmp, BLOCK_SIZE);
}

void hmac_update(hmac_state *state, unsigned char *data, int count)
{
    SHA256_Update(&state->inner, data, count);   
}

void hmac_result(hmac_state *state, unsigned char *result)
{
    unsigned char tmp[32];
    SHA256_Final(tmp, &state->inner);
    SHA256_Update(&state->outer, tmp, 32);
    SHA256_Final(result, &state->outer);
}

#ifdef TEST

static void print_hex(unsigned char *data, int len)
{
    int i;
    for (i = 0; i < len; i++) {
      printf("%02hhx ", data[i]);
    }
    printf("\n");
}


int main(int argc, char **argv)
{
    unsigned char result[32];
    hmac_state state;
    char *key = "key";  
    char *data = "The quick brown fox jumps over the lazy dog";  
    
    hmac_init(&state, (unsigned char*)key, strlen(key));
    hmac_update(&state, (unsigned char*)data, strlen(data));
    hmac_result(&state, result);
    
    print_hex(result, 32);
    return 0;    
}

#endif