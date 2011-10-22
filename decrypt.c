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
