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

#ifndef _DRPM_H_
#define _DRPM_H_

//errors
#define DRPM_ERR_OK 0       /* no error */
#define DRPM_ERR_MEMORY 1   /* memory allocation error */
#define DRPM_ERR_ARGS 2     /* bad arguments */
#define DRPM_ERR_IO 3       /* I/O error */
#define DRPM_ERR_FORMAT 4   /* wrong file format */
#define DRPM_ERR_CONFIG 5   /* misconfigured external library */
#define DRPM_ERR_OTHER 6    /* unspecified/unknown error */

//delta types
#define DRPM_TYPE_STANDARD 0
#define DRPM_TYPE_RPMONLY 1

//compression types
#define DRPM_COMP_NONE 0
#define DRPM_COMP_GZIP 1
#define DRPM_COMP_BZIP2 2
#define DRPM_COMP_LZMA 3
#define DRPM_COMP_XZ 4

//info tags
#define DRPM_TAG_FILENAME 0
#define DRPM_TAG_VERSION 1
#define DRPM_TAG_TYPE 2
#define DRPM_TAG_COMP 3
#define DRPM_TAG_SEQUENCE 4
#define DRPM_TAG_SRCNEVR 5
#define DRPM_TAG_TGTNEVR 6
#define DRPM_TAG_TGTSIZE 7
#define DRPM_TAG_TGTMD5 8

//drpm structure
struct drpm;

//function prototypes
int drpm_destroy(struct drpm **delta); /* Frees memory pointed to by <*delta>
and sets <*delta> to NULL. */

int drpm_get_uint(struct drpm *delta, int tag, unsigned *target); /* Fetches 
information (representable as an unsigned integer) identified by <tag> from
<delta> and copies it to adress pointed to by <target>. */

int drpm_get_string(struct drpm *delta, int tag, char **target); /* Fetches 
string-type information identified by <tag> from <delta>, copies it to space
previously allocated by the function itself and saves the adress to <*target>.
(Should be freed manually by the user when no longer needed.) */

int drpm_read(struct drpm **delta, const char *filename); /* Reads information
from a deltarpm package <filename> into <*delta> */

#endif
