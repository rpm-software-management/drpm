/*
    Authors:
        Pavel Tobias <ptobias@redhat.com>

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

#include <stdlib.h>

#include "drpm.h"
#include "drpm_private.h"

void dump_hex(char *dest, char *source, size_t count)
{
    char digits[] = "0123456789abcdef";

    dest[count * 2] = '\0';

    while (count--) {
        dest[count * 2] = digits[source[count] >> 4 & 0x0F];
        dest[count * 2 + 1] = digits[source[count] & 0x0F];
    }
}

uint32_t parse_be32(char *buffer)
{
    return (0xFF000000 & (buffer[0] << 24)) |
           (0x00FF0000 & (buffer[1] << 16)) |
           (0x0000FF00 & (buffer[2] << 8)) |
           (0x000000FF & buffer[3]);
}
