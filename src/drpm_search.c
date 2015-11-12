/*
    Authors:
        Matej Chalk <mchalk@redhat.com>

    Copyright (C) 2015 Red Hat

    This program is licensed under the BSD license, read LICENSE.BSD
    for further information.
*/

/*
  Copyright 2004,2005 Michael Schroeder

  rewritten from bsdiff.c,
      http://www.freebsd.org/cgi/cvsweb.cgi/src/usr.bin/bsdiff
  added library interface and hash method, enhanced suffix method.
*/
/*-
 * Copyright 2003-2005 Colin Percival
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "drpm.h"
#include "drpm_private.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <divsufsort.h>

#define MIN_MISMATCHES 32

static size_t match_len(const unsigned char *, size_t, const unsigned char *, size_t);
static size_t suffix_search(const int *, const unsigned char *, size_t,
                            const unsigned char *, size_t, size_t, size_t, size_t *);

size_t match_len(const unsigned char *old, size_t old_len,
                 const unsigned char *new, size_t new_len)
{
    size_t i;
    size_t len = MIN(old_len, new_len);

    for (i = 0; i < len; i++)
        if (old[i] != new[i])
            break;

    return i;
}

/**************************** suffix sort ****************************/

struct sfxsrt {
    int *I;         // suffix array
    size_t F[257];  // min. number of preceding suffixes for each byte value
};

int sfxsrt_create(struct sfxsrt **suf, const unsigned char *old, size_t old_len)
{
    int *I;
    size_t F[257] = {0};

    if (suf == NULL || old == NULL)
        return DRPM_ERR_PROG;

    if (old_len > INT_MAX)
        return DRPM_ERR_OVERFLOW;

    if ((*suf = malloc(sizeof(struct sfxsrt))) == NULL ||
        (I = malloc((old_len + 3) * sizeof(int))) == NULL) // TODO
        return DRPM_ERR_MEMORY;

    if (divsufsort(old, I, (int)old_len) != 0) {
        free(I);
        free(*suf);
        return DRPM_ERR_OTHER;
    }

    for (size_t i = 0; i < old_len; i++)
        F[old[i]]++;
    for (size_t i = 1; i < 257; i++)
        F[i] += F[i-1];
    for (size_t i = 256; i > 0; i--)
        F[i] = F[i-1];
    F[0] = 0;

    (*suf)->I = I;
    for (size_t i = 0; i < 257; i++)
        (*suf)->F[i] = F[i];

    return DRPM_ERR_OK;
}

void sfxsrt_free(struct sfxsrt **suf)
{
    free((*suf)->I);
    free(*suf);
}

size_t sfxsrt_search(struct sfxsrt *suf,
                     const unsigned char *old, size_t old_len,
                     const unsigned char *new, size_t new_len,
                     size_t last_offset, size_t scan,
                     size_t *pos_ret, size_t *len_ret)
{
    size_t len = 0;
    size_t old_score = 0;
    size_t miniscan = scan;

    while (scan < new_len) {
        len = suffix_search(suf->I, old, old_len, new, new_len,
                            suf->F[new[scan]] + 1, suf->F[new[scan] + 1], // TODO
                            pos_ret);

        const size_t miniscan_limit = MIN(scan + len, old_len - last_offset);
        for ( ; miniscan < miniscan_limit; miniscan++)
            if (old[miniscan + last_offset] == new[miniscan])
                old_score++;
        miniscan = scan + len;

        if (len > 0 && len == old_score) {
            scan += len;
            miniscan = scan;
            old_score = 0;
            continue;
        }

        if (len - old_score > MIN_MISMATCHES)
            break;

        if (scan + last_offset < old_len &&
            old[scan + last_offset] == new[scan])
            old_score--;

        scan++;
    }

    *len_ret = len;

    return scan;
}

size_t suffix_search(const int *sfxar,
                     const unsigned char *old, size_t old_len,
                     const unsigned char *new, size_t new_len,
                     size_t start, size_t end,
                     size_t *pos_ret)
{
    size_t halfway;
    size_t len_1;
    size_t len_2;

    if (start > end)
        return 0;

    if (start == end) {
        *pos_ret = sfxar[start];
        return match_len(old + sfxar[start], old_len - sfxar[start], new, new_len);
    }

    while (end - start >= 2) {
        halfway = start + (end - start) / 2;
        if (memcmp(old + sfxar[halfway], new,
                   MIN(new_len, old_len - sfxar[halfway])) < 0)
            start = halfway;
        else
            end = halfway;
    }

    len_1 = match_len(old + sfxar[start], old_len - sfxar[start], new, new_len);
    len_2 = match_len(old + sfxar[end],   old_len - sfxar[end],   new, new_len);

    *pos_ret = sfxar[len_1 > len_2 ? start : end];

    return MAX(len_1, len_2);
}
