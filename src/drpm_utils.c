/*
    Authors:
        Pavel Tobias <ptobias@redhat.com>
        Matej Chalk <mchalk@redhat.com>

    Copyright (C) 2014 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "drpm.h"
#include "drpm_private.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <sys/types.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

static bool resize(void **, size_t, size_t, size_t);

/* Reads 16-byte integer in network byte order buffer. */
uint16_t parse_be16(const unsigned char buffer[2])
{
    return (0xFF00 & (buffer[0] << 8)) | (0x00FF & buffer[1]);
}

/* Reads 32-byte integer in network byte order from buffer. */
uint32_t parse_be32(const unsigned char buffer[4])
{
    return (0xFF000000 & (buffer[0] << 24)) |
           (0x00FF0000 & (buffer[1] << 16)) |
           (0x0000FF00 & (buffer[2] << 8)) |
           (0x000000FF & buffer[3]);
}

/* Reads 64-byte integer in network byte order from buffer. */
uint64_t parse_be64(const unsigned char buffer[8])
{
    return (0xFF00000000000000 & ((uint64_t)buffer[0] << 56)) |
           (0x00FF000000000000 & ((uint64_t)buffer[1] << 48)) |
           (0x0000FF0000000000 & ((uint64_t)buffer[2] << 40)) |
           (0x000000FF00000000 & ((uint64_t)buffer[3] << 32)) |
           (0x00000000FF000000 & ((uint64_t)buffer[4] << 24)) |
           (0x0000000000FF0000 & ((uint64_t)buffer[5] << 16)) |
           (0x000000000000FF00 & ((uint64_t)buffer[6] << 8)) |
           (0x00000000000000FF & (uint64_t)buffer[7]);
}

/* Writes 32-byte integer in network byte order to buffer. */
void create_be32(uint32_t in, unsigned char out[4])
{
    out[0] = in >> 24;
    out[1] = in >> 16;
    out[2] = in >> 8;
    out[3] = in;
}

/* Writes 64-byte integer in network byte order to buffer. */
void create_be64(uint64_t in, unsigned char out[8])
{
    out[0] = in >> 56;
    out[1] = in >> 48;
    out[2] = in >> 40;
    out[3] = in >> 32;
    out[4] = in >> 24;
    out[5] = in >> 16;
    out[6] = in >> 8;
    out[7] = in;
}

int md5_update_be32(MD5_CTX *md5, uint32_t number)
{
    unsigned char be32[4];

    create_be32(number, be32);

    return MD5_Update(md5, be32, 4);
}

/* Represents array of bytes pointed to by <source> of size <count>
 * as human-readable ASCII hexadecimals and stores this string in
 * <dest> (should be at least of size <count> * 2 + 1). */
void dump_hex(char *dest, const unsigned char *source, size_t count)
{
    char digits[] = "0123456789abcdef";

    dest[count * 2] = '\0';

    while (count--) {
        dest[count * 2] = digits[source[count] >> 4 & 0x0F];
        dest[count * 2 + 1] = digits[source[count] & 0x0F];
    }
}

/* Converts human-readable hexadecimal string (<source>)
 * to array of bytes (<dest>), which should have enough space for
 * strlen(<source>) / 2 bytes.
 * Returns length of array, or -1 on error. */
ssize_t parse_hex(unsigned char *dest, const char *source)
{
    ssize_t byte;
    size_t count;

    count = strlen(source) / 2;

    for (size_t i = 0; i < count; i++, source += 2) {
        if ((byte = parse_hexnum(source, 2)) < 0)
            return -1;
        dest[i] = byte;
    }

    return count;
}

ssize_t parse_hexnum(const char *str, size_t size)
{
    size_t ret = 0;

    for (size_t i = 0; i < size; i++) {
        ret *= 16;
        if (isdigit(str[i]))
            ret += str[i] - '0';
        else if (isxdigit(str[i]))
            ret += toupper(str[i]) - 'A' + 0xA;
        else
            return -1;
    }

    return ret;
}

bool parse_md5(unsigned char *dest, const char *source)
{
    return parse_hex(dest, source) == MD5_DIGEST_LENGTH;
}

bool parse_sha256(unsigned char *dest, const char *source)
{
    return parse_hex(dest, source) == SHA256_DIGEST_LENGTH;
}

/* Reallocates memory for <*buffer> <threshhold> bytes at a time>. */
bool resize(void **buffer, size_t members_count, size_t member_size, size_t threshhold)
{
    void *buf_tmp;

    if (members_count % threshhold == 0) {
        if ((buf_tmp = realloc(*buffer,
             member_size * (members_count + threshhold))) == NULL)
            return false;
        *buffer = buf_tmp;
    }

    return true;
}

bool resize16(void **buffer, size_t members_count, size_t member_size)
{
    return resize(buffer, members_count, member_size, 16);
}

bool resize32(void **buffer, size_t members_count, size_t member_size)
{
    return resize(buffer, members_count, member_size, 32);
}
