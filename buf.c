/* Copyright © 2011 Noa Resare */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buf.h"

int buf_open(char *filename, unsigned int size, buf_state **state) {
    buf_state* s;

    s = malloc(sizeof(buf_state));
    s->buf = malloc(size);
    s->size = size;
    
    if ((s->fd = open(filename, O_RDONLY)) == -1) {
        return -1;
    }

    s->start = 0;
    s->end = read(s->fd, s->buf, size);
    if (s->end == 0) {
      // empty file
      return -2;
    }
    *state = s;
    return 0;
}

int buf_read(buf_state *state, int count, unsigned char **target) {

    
    if (state->end - state->start < count) {
        if (count > BUFSIZ) {
            // FIXME: we can't serve requests this large
            return -1;
        } else {
            // move remaining data to beginning of buffer
            int move_count = state->end - state->start;
            
            memcpy(state->buf, state->buf + state->start, move_count);

            int read_count = read(state->fd, state->buf + move_count, 
                              state->size - move_count);
            if (read_count == -1) {
                return -2;
            }
            state->start = 0;
            state->end = move_count + read_count;
        }
    }
    *target = state->buf + state->start;
    state->start += count;    
    return 0;
}

int buf_close(buf_state *state) {
    int i = close(state->fd);
    free(state->buf);
    free(state);
    return i;
}

#ifdef TEST
static void cmp(void *a, void *b, int count) {
    char a_copy[count + 1];
    char b_copy[count + 1];
    int i;
    a_copy[count] = '\0';
    b_copy[count] = '\0';
    memcpy(a_copy, a, count);
    memcpy(b_copy, b, count);
    i = memcmp(a, b, count);
    if (i != 0) {
        printf("read failed, got '%s' instead of '%s'\n", a_copy, b_copy);
    } else {
        printf("read succeeded\n");
    }
}

int main(int argc, char **argv) {
    buf_state *s;
    unsigned char *p;
    char *expected0 = "01234567";
    char *expected1 = "89abcdefghijklmn";
    char *expected2 = "opqrstuvwxyzABCD";
    
    buf_open("test/test.txt", 32, &s);
    buf_read(s, 8, &p);

    cmp(p, expected0, 8);
    buf_read(s, 16, &p);
    cmp(p, expected1, 16);
    buf_read(s, 16, &p);
    cmp(p, expected2, 16);
    
    buf_close(s);
    
    return 0;
}
#endif