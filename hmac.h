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