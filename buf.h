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
    