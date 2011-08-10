/* Copyright © 2011 Noa Resare */

#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/uio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/sha.h>

#include "twofish.h"
#include "hmac.h"
#include "buf.h"
#include "pws.h"

static void print_hex(unsigned char *data, int len)
{
    int i;
    for (i = 0; i < len; i++) {
      printf("%02hhx ", data[i]);
    }
    printf("\n");
}

static unsigned int read_uint32_le(unsigned char *buf)
{
    return buf[0] + ((int)buf[1] << 8) + ((int)buf[2] << 16) + ((int)buf[3] << 24);
}

/**
 * Stretches the provided password according to http://www.schneier.com/paper-low-entropy.pdf using
 * the given salt and the given number of iterations and write the resulting 32 byte long stretched
 * password to target.
 */
static void stretch(char *password, unsigned char *salt, int iterations, unsigned char *target)
{
    int i;
    SHA256_CTX c;
    unsigned char tmp[32];
    
    SHA256_Init(&c);
    SHA256_Update(&c, password, strlen(password));
    SHA256_Update(&c, salt, 32);
    SHA256_Final(tmp, &c);
    
    for (i = 0; i < iterations; i++) {
      SHA256(tmp, 32, tmp);
    }
    memcpy(target, tmp, 32);    
}

/** 
 * Reads and descrypts 32 bytes of data using the provided key in ECB mode and writes
 * the resulting data to the buffer referenced by result.
 */
static void decrypt_twofish_ecb_32(unsigned char *key, unsigned char *buf, unsigned char *result)
{
    Twofish_key twokey;
    Twofish_initialise();
    Twofish_prepare_key(key, 32, &twokey);
    Twofish_decrypt(&twokey, buf, result);
    Twofish_decrypt(&twokey, buf + 16, result + 16);
}

typedef struct decryptor {
    Twofish_key twokey;
    unsigned char cbc_state[16];
} decryptor;

static void setup_decryptor(unsigned char *key, unsigned char *iv, unsigned char *hmac_key,
        decryptor *dec)
{
    Twofish_initialise();
    Twofish_prepare_key(key, 32, &dec->twokey);
    memcpy(dec->cbc_state, iv, 16);
}

static void decrypt_cbc(decryptor *dec, unsigned char *in, unsigned char *out)
{
    unsigned int i;
    Twofish_decrypt(&dec->twokey, in, out);
    for (i = 0; i < 16; i++) {
        out[i] = out[i] ^ dec->cbc_state[i];
        dec->cbc_state[i] = in[i];
    }
}


static void read_blocks(decryptor *dec, buf_state *buf)
{
    int field_size = 0;
    unsigned char *p, tmp[16], *data_start;

    
    while (1) {
        buf_read(buf, 16, &p);
        if (memcmp(p, "PWS3-EOFPWS3-EOF", 16) == 0) {
            printf("Found EOF marker\n");
            break;
        }
        decrypt_cbc(dec, p, tmp);

        field_size = read_uint32_le(tmp);
        printf("record size: %d\n", field_size);
        
    
        print_hex(tmp, 16);
        
    }
}

typedef struct field {
    int len;
    unsigned char type;
    unsigned char *data;
    struct field *next;
} field;

int pws_read_safe(char *filename, char *password)
{
    int retval, iter;
    unsigned char salt[32], stretched[32], hashed_stretched[32], k[32], l[32];
    
    decryptor dec;
    
    buf_state *buf;
    unsigned char *p;
    
    if ((retval = buf_open(filename, BUFSIZ, &buf))) {
        return retval;
    }
    buf_read(buf, 4, &p);
    retval = memcmp("PWS3", p, 4);
    if (retval != 0) {
        fprintf(stderr, "Wrong file signature");
        buf_close(buf);
        return -1;
    }
    
    buf_read(buf, 32, &p);
    memcpy(salt, p, 32);
    print_hex(salt,32);

    buf_read(buf, 4, &p);
    iter = read_uint32_le(p);

    stretch(password, salt, iter, stretched);
    
    SHA256(stretched, 32, hashed_stretched);    

    buf_read(buf, 32, &p);
    retval = memcmp(hashed_stretched, p, 32);
    if (retval != 0) {
        fprintf(stderr, "Wrong password\n");
        buf_close(buf);
        return -3;
    } else {
        printf("Password matched!\n");
    }
    
    buf_read(buf, 32, &p);
    decrypt_twofish_ecb_32(stretched, p, k);
    buf_read(buf, 32, &p);
    decrypt_twofish_ecb_32(stretched, p, l);    

    buf_read(buf, 16, &p);
    setup_decryptor(k, p, l, &dec);
    
    read_blocks(&dec, buf);
    
    /*
    retval = memcmp(hmac, buf + pos, 32);
    if (retval != 0) {
        fprintf(stderr, "Checksum mismatch\n");
        close(fd);
        return -4;
    } else {
        printf("Checksum matched\n");
    }
     */
    
    buf_close(buf);
    return 0;
}

