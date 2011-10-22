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

#include "twofish.h"

typedef struct cbc_state {
    Twofish_key twokey;
    unsigned char cbc_state[16];
} cbc_state;

/**
 * Sets up the cbc_state with the given key and initial vector iv.
 * @param key a pointer to 32 bytes key data
 * @param iv a pointer 16 bytes of initial vector.
 */
void decrypt_setup(cbc_state *state, unsigned char *key, unsigned char *iv);

/**
 * Decrypts 16 bytes of data from the buffer in and writes the decrypted 16 bytes
 * of data to target. 
 */
void decrypt_cbc(cbc_state *state, unsigned char *in, unsigned char *target);

/** 
 * Reads and descrypts 32 bytes of data using the provided key in ECB mode and writes
 * the resulting data to the buffer referenced by result.
 */
void decrypt_twofish_ecb_32(unsigned char *key, unsigned char *buf, unsigned char *result);