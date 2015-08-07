/*
    Authors:
        Matej Chalk <mchalk@redhat.com>

    Copyright (C) 2004,2005 Michael Schroeder (mls@suse.de)
    Copyright (C) 2015 Red Hat

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

#include <stdint.h>
#include <stdbool.h>

#define DELTARPM_COMP_UN 0
#define DELTARPM_COMP_GZ 1
#define DELTARPM_COMP_BZ_20 2
#define DELTARPM_COMP_GZ_RSYNC 3
#define DELTARPM_COMP_BZ_17 4
#define DELTARPM_COMP_LZMA 5
#define DELTARPM_COMP_XZ 6

#define DELTARPM_COMP_BZ DELTARPM_COMP_BZ_20

#define DELTARPM_MKCOMP(comp, level) ((comp) | ((level) << 8))
#define DELTARPM_COMPALGO(comp) ((comp) & 255)
#define DELTARPM_COMPLEVEL(comp) (((comp) >> 8) & 255)

bool deltarpm_decode_comp(uint32_t deltarpm_comp, unsigned short *comp, unsigned short *level)
{
    switch (DELTARPM_COMPALGO(deltarpm_comp)) {
    case DELTARPM_COMP_UN:
        *comp = DRPM_COMP_NONE;
        break;
    case DELTARPM_COMP_GZ:
    case DELTARPM_COMP_GZ_RSYNC:
        *comp = DRPM_COMP_GZIP;
        break;
    case DELTARPM_COMP_BZ_20:
    case DELTARPM_COMP_BZ_17:
        *comp = DRPM_COMP_BZIP2;
        break;
    case DELTARPM_COMP_LZMA:
        *comp = DRPM_COMP_LZMA;
        break;
    case DELTARPM_COMP_XZ:
        *comp = DRPM_COMP_XZ;
        break;
    default:
        return false;
    }

    if (level != NULL)
        *level = DELTARPM_COMPLEVEL(deltarpm_comp);

    return true;
}

bool deltarpm_encode_comp(uint32_t *deltarpm_comp, unsigned short comp, unsigned short level)
{
    switch (comp) {
    case DRPM_COMP_NONE:
        *deltarpm_comp = DELTARPM_MKCOMP(DELTARPM_COMP_UN, level);
        break;
    case DRPM_COMP_GZIP:
        *deltarpm_comp = DELTARPM_MKCOMP(DELTARPM_COMP_GZ, level);
        break;
    case DRPM_COMP_BZIP2:
        *deltarpm_comp = DELTARPM_MKCOMP(DELTARPM_COMP_BZ, level);
        break;
    case DRPM_COMP_LZMA:
        *deltarpm_comp = DELTARPM_MKCOMP(DELTARPM_COMP_LZMA, level);
        break;
    case DRPM_COMP_XZ:
        *deltarpm_comp = DELTARPM_MKCOMP(DELTARPM_COMP_XZ, level);
        break;
    default:
        return false;
    }

    return true;
}
