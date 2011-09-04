/* Copyright © 2011 Noa Resare */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "pws.h"

#define FILENAME "/Users/noa/fun/libpws/test/safe.psafe3"

int main(int argc, char **argv)
{
    int retval;

    printf("PWD is '%s'\n", getenv("PWD"));
    pws_database *database;
    
    if ((retval = pws_read_safe(FILENAME, "test", &database))) {
        fprintf(stderr, "pws_read_safe() returned %d\n", retval);
        fprintf(stderr, "Could not open '%s': %s\n", FILENAME, strerror(errno));
    }

    return 0;
}