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

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "pws.h"

#define FILENAME "/Users/noa/fun/libpws/test/safe.psafe3"

static void print_hex(unsigned char *data, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        printf("%02hhx ", data[i]);
    }
    printf("\n");
}

static void print_records(pws_record *r, int count)
{
    int i, j;
    for (i = 0; i < count; i++) {
        for (j = 0; j < r[i].field_count; j++) {
            printf("record %d value %d type %d ", i, j, r[i].fields[j].type);
            print_hex(r[i].fields[j].value, r[i].fields[j].value_length);
        }
    }
}

int main(int argc, char **argv)
{
    int retval, i;

    printf("PWD is '%s'\n", getenv("PWD"));
    pws_database *db;
    
    if ((retval = pws_read_safe(FILENAME, "test", &db))) {
        fprintf(stderr, "pws_read_safe() returned %d\n", retval);
        fprintf(stderr, "Could not open '%s': %s\n", FILENAME, strerror(errno));
    }
    
    for (i = 0; i < db->header_count; i++) {
        printf("header %d: type: %d ", i, db->headers[i].type);
        print_hex(db->headers[i].value, db->headers[i].value_length);
    }
    print_records(db->records, db->record_count);
    return 0;
}