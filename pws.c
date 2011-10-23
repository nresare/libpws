/* 
 libpwsafe - a portable implementation of the passwordsafe format
 Copyright © 2011 Noa Resare 
 
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/uio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "sph_sha2.h"

#include "twofish.h"
#include "hmac.h"
#include "buf.h"
#include "pws.h"
#include "decrypt.h"

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
    sph_sha256_context c;
    unsigned char tmp[32];
    
    sph_sha256_init(&c);
    sph_sha256(&c, password, strlen(password));
    sph_sha256(&c, salt, 32);
    sph_sha256_close(&c, tmp);
    
    for (i = 0; i < iterations; i++) {
        sph_sha256_init(&c);
        sph_sha256(&c, tmp, 32);
        sph_sha256_close(&c, tmp);
    }
    memcpy(target, tmp, 32);    
}

typedef struct field {
    int len;
    unsigned char type;
    unsigned char *data;
    struct field *next;
} field;

typedef struct header {
    unsigned char key[32], iv[16], hmac_key[32];
} header;

static void add_field(field *f, field **fields) {
    field *cur = *fields;
    
    assert(f->next == NULL);
    if (cur == NULL) {
        *fields = f;
        return;
    }
    while (cur->next != NULL) {
        cur = cur->next;
    }
    cur->next = f;
}

/**
 * Reads the data blocks from buf and adds the found data to the fields linked list.
 * 
 * @return 0 on success, -1 if the checksum check fails, -2 if malloc fails
 */
static int read_blocks(header *hdr, buf_state *buf, field **fields)
{
    int field_size, extra_blocks, i;
    unsigned char *p, tmp[16], *data_target, hmac_data[32];
    cbc_state cbc;
    hmac_state hmac;
    field *f = malloc(sizeof(field));
    if (!f) {
        return -2;
    }
    
    decrypt_setup(&cbc, hdr->key, hdr->iv);
    
    hmac_init(&hmac, hdr->hmac_key, 32);
    
    while (1) {
        buf_read(buf, 16, &p);
        if (memcmp(p, "PWS3-EOFPWS3-EOF", 16) == 0) {
            printf("Found EOF marker\n");
            break;
        }
        decrypt_cbc(&cbc, p, tmp);
        assert(f->next == NULL);
        field_size = read_uint32_le(tmp);
        f->type = *(tmp + 4);

        if (field_size > 0) {
            data_target = malloc(field_size);
            if (data_target == NULL) {
                return -2;
            }
            memcpy(data_target, tmp + 5, field_size > 11 ? 11 : field_size);
        }

        extra_blocks = (field_size + 4) / 16;

        for (i = 0; i < extra_blocks; i++) {
            int offset = 11 + (i * 16);
            int len = field_size - offset > 16 ? 16 : field_size - offset;
            buf_read(buf, 16, &p);
            decrypt_cbc(&cbc, p, tmp);
            memcpy(data_target + offset, tmp, len);
        }
        f->len = field_size;


        if (field_size > 0) {
            hmac_update(&hmac, data_target, field_size);
            f->data = data_target;
        }

        add_field(f, fields);
        f = malloc(sizeof(field));
        if (!f) {
            return -2;
        }
        memset(f, 0, sizeof(*f));
        
    }
    buf_read(buf, 32, &p);
    hmac_result(&hmac, hmac_data);
    i = memcmp(hmac_data, p, 32);
    if (i == 0) {
        return 0;
    } else {
        return -1;
    }
}

/**
 * Reads the fixed header fields from verifies the password and populates 
 * the header fields.
 * 
 * @return 0 on success, -1 if the password check fails.
 */
static int read_header(header *hdr, char *password, buf_state *buf)
{
    unsigned char *p, stretched[32], salt[32], hashed_stretched[32];
    int iter, retval;
    sph_sha256_context c;
    
    buf_read(buf, 32, &p);
    memcpy(salt, p, 32);

    buf_read(buf, 4, &p);
    iter = read_uint32_le(p);

    stretch(password, salt, iter, stretched);
    
    sph_sha256_init(&c);
    sph_sha256(&c, stretched, 32);
    sph_sha256_close(&c, hashed_stretched);

    buf_read(buf, 32, &p);
    retval = memcmp(hashed_stretched, p, 32);
    if (retval != 0) {
        fprintf(stderr, "Wrong password\n");
        buf_close(buf);
        return -1;
    } else {
        printf("Password matched!\n");
    }
    
    buf_read(buf, 32, &p);
    decrypt_twofish_ecb_32(stretched, p, hdr->key);
    buf_read(buf, 32, &p);
    decrypt_twofish_ecb_32(stretched, p, hdr->hmac_key);    

    buf_read(buf, 16, &p);
    memcpy(hdr->iv, p, 16);
    
    
    return 0;
}

static int make_database(field *fields, pws_database **database)
{
    pws_database *db = *database;
    int record_idx = -1;
    int field_idx = 0;
    
    if (((db = malloc(sizeof(pws_database))) == NULL)) {
        return -1;
    }
    db->header_count = 0;
    db->record_count = -1;

    field *next;
    field *cur = fields;
    while (cur) {
        if (db->record_count == -1) {
            if (cur->type == 255) {
                db->record_count = 0;
            } else {
                db->header_count++;
            }
        } else {
            if (cur->type == 255) {
                db->record_count++;
            }
        }
        cur = cur->next;
    }
    printf("Found %d headers and %d records\n", db->header_count, db->record_count);
    
    if (((db->headers = malloc(sizeof(pws_field) * db->header_count)) == NULL)) {
        return -1;
    }
    
    if (((db->records = malloc(sizeof(pws_record) * db->record_count)) == NULL)) {
        return -1;
    }
    
    // count the number of fields in each record.
    cur = fields;
    while (cur) {
        if (cur->type == 255) {
            if (record_idx > -1) {
                db->records[record_idx].field_count = field_idx;
                if (((db->records[record_idx].fields = malloc(sizeof(pws_field) * field_idx)) == NULL)) {
                    return -1;
                }
            }
            record_idx++;
            field_idx = 0;
        } else {
            field_idx++;
        }
        cur = cur->next;
    }

    record_idx = -1;
    
    // populate headers and records
    cur = fields;
    while (cur) {
        if (cur->type == 255) {
            record_idx++;
            field_idx = 0;
        } else {
            if (record_idx == -1) {
                db->headers[field_idx].type = cur->type;
                db->headers[field_idx].value_length = cur->len;
                db->headers[field_idx].value = cur->data;
            } else {
                db->records[record_idx].fields[field_idx].type = cur->type;
                db->records[record_idx].fields[field_idx].value_length = cur->len;
                db->records[record_idx].fields[field_idx].value = cur->data;
            }
            field_idx++;
        }
        cur = cur->next;
    }
    
    // free the fields list
    cur = fields;
    while (cur) {
        next = cur->next;
        free(cur);
        cur = next;
    }
    
    
    *database = db;
    return 0;
}

int pws_read_safe(char *filename, char *password, pws_database **database)
{
    int retval;
    header hdr;
    
    field *fields = NULL;
    
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
    
    if ((retval = read_header(&hdr, password, buf))) {
        buf_close(buf);
        return retval;
    }

    
    if ((read_blocks(&hdr, buf, &fields))) {
        buf_close(buf);
        return retval;
    }    
    
    if ((make_database(fields, database))) {
        buf_close(buf);
        return retval;
    }
    buf_close(buf);
    return 0;
}

