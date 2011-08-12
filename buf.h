/* Copyright © 2011 Noa Resare */

typedef struct buf_state {
    unsigned char *buf;
    ssize_t start, end, size;
    int fd;
} buf_state;

/**
 * Allocates a buffer with the given size and fills it with data from 
 * the given file.
 * 
 * @return 0 if everything went ok. -1 if file open fails. -2 if the
 * file is empty.
 */
int buf_open(char *filename, unsigned int size, buf_state **state);

/**
 * Updates the target pointer to point to count bytes in the internal
 * buf_state. If needed, data is moved around in the buffer and new
 * data is read from the backing file.
 *
 * @return 0 if everything went ok. -1 if the request is bigger than
 * the backing buffer size, -2 if a read from the file fails (check errno
 * for details)
 */
int buf_read(buf_state *state, int count, unsigned char **target);

/**
 * Frees the memory associated with state
 */
int buf_close(buf_state *state);
    