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

#include <stdlib.h>
#include <string.h>

#define MIN_MISMATCHES 32

static size_t match_len(const unsigned char *, size_t, const unsigned char *, size_t);
static int bucketsort(long long *, long long *, size_t, size_t);
static void suffix_split(long long *, long long *, size_t, size_t, size_t);
static size_t suffix_search(const long long *, const unsigned char *, size_t,
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
    long long *I;   // suffix array
    size_t F[257];  // min. number of preceding suffixes for each byte value
};

int sfxsrt_create(struct sfxsrt **suf, const unsigned char *old, size_t old_len)
{
    int error = DRPM_ERR_OK;
    long long *I = NULL;
    long long *V = NULL;
    size_t h;
    size_t bucket_len;
    size_t len;
    size_t val;
    size_t l;
    size_t i;
    uint32_t oldv;
    size_t F[257] = {0};

    if (suf == NULL || old == NULL)
        return DRPM_ERR_PROG;

    if ((*suf = malloc(sizeof(struct sfxsrt))) == NULL ||
        (I = malloc(sizeof(long long) * (old_len + 3))) == NULL ||
        (V = malloc(sizeof(long long) * (old_len + 3))) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup_fail;
    }

    if (old_len > 0xFFFFFF) {
        bucket_len = 0x1000002;
        h = 3;

        F[old[0]]++;
        F[old[1]]++;
        oldv = old[0] << 8 | old[1];
        for (size_t i = 2; i < old_len; i++) {
            F[old[i]]++;
            oldv = (oldv & 0xFFFF) << 8 | old[i];
            V[i - 2] = oldv + 2;
        }
        oldv = (oldv & 0xFFFF) << 8;
        V[old_len - 2] = oldv + 2;
        oldv = (oldv & 0xFFFF) << 8;
        V[old_len - 1] = oldv + 2;
        len = old_len + 2;
        V[len - 2] = 1;
        V[len - 1] = 0;
    } else {
        bucket_len = 0x10001;
        h = 2;

        F[old[0]]++;
        oldv = old[0];
        for (size_t i = 1; i < old_len; i++) {
            F[old[i]]++;
            oldv = (oldv & 0xFF) << 8 | old[i];
            V[i - 1] = oldv + 1;
        }
        oldv = (oldv & 0xFF) << 8;
        V[old_len - 1] = oldv + 1;
        len = old_len + 1;
        V[len - 1] = 0;
    }

    val = len;
    for (unsigned short i = 256; i > 0; val -= F[--i])
        F[i] = val;
    F[0] = val;

    if ((error = bucketsort(I, V, len, bucket_len)) != DRPM_ERR_OK)
        goto cleanup_fail;

    len++;
    for ( ; I[0] != -(long long)len; h += h) {
        l = 0;
        for (i = 0; i < len; ) {
            if (I[i] < 0) {
                l -= I[i];
                i -= I[i];
            } else {
                if (l > 0)
                    I[i - l] = -(long long)l;
                l = V[I[i]] + 1 - i;
                suffix_split(I, V, i, l, h);
                i += l;
                l = 0;
            }
        }
        if (l > 0)
            I[i - l] = -(long long)l;
    }

    for (i = 0; i < len; i++)
        I[V[i]] = i;

    (*suf)->I = I;
    memcpy((*suf)->F, F, sizeof(size_t) * 257);

    goto cleanup;

cleanup_fail:
    free(*suf);
    free(I);

cleanup:
    free(V);

    return error;
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
                            suf->F[new[scan]] + 1, suf->F[new[scan] + 1],
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

int bucketsort(long long *I, long long *V, size_t len, size_t bucket_len)
{
    size_t *B;
    size_t c, d, i, j, g;

    if ((B = calloc(bucket_len, sizeof(size_t))) == NULL)
        return DRPM_ERR_MEMORY;

    for (i = len; i > 0; i--) {
        c = V[i - 1];
        V[i - 1] = B[c];
        B[c] = i;
    }

    for (j = bucket_len - 1, i = len; i > 0; j--) {
        for (d = B[j], g = i; d > 0; i--) {
            c = d - 1;
            d = V[c];
            V[c] = g;
            I[i] = (d == 0 && g == i) ? -1 : (long long)c;
        }
    }

    V[len] = 0;
    I[0] = -1;

    free(B);

    return DRPM_ERR_OK;
}

void suffix_split(long long *I, long long *V, size_t start, size_t len, size_t h)
{
    size_t i, j, k, jj, kk;
    long long x, tmp;
    const size_t end = start + len;

    if (len < 16) {
        for (k = start; k < end; k += j) {
            j = 1;
            x = V[I[k] + h];
            for (i = 1; k + i < end; i++) {
                if (V[I[k+i] + h] < x) {
                    x = V[I[k+i] + h];
                    j = 0;
                }
                if (V[I[k+i] + h] == x) {
                    tmp = I[k+j];
                    I[k+j] = I[k+i];
                    I[k+i] = tmp;
                    j++;
                }
            }
            for (i = 0; i < j; i++)
                V[I[k + i]] = k + j - 1;
            if (j == 1)
                I[k] = -1;
        }
        return;
    }

    x = V[I[start + len/2] + h];
    jj = 0;
    kk = 0;
    for (i = start; i < end; i++) {
        if (V[I[i] + h] < x)
            jj++;
        if (V[I[i] + h] == x)
            kk++;
    }
    jj += start;
    kk += jj;

    i = start;
    j = 0;
    k = 0;
    while (i < jj) {
        if (V[I[i] + h] < x) {
            i++;
        } else if (V[I[i] + h] == x) {
            tmp = I[i];
            I[i] = I[jj + j];
            I[jj + j] = tmp;
            j++;
        } else {
            tmp = I[i];
            I[i] = I[kk + k];
            I[kk + k] = tmp;
            k++;
        }
    }

    while (jj + j < kk) {
        if (V[I[jj+j] + h] == x) {
            j++;
        } else {
            tmp = I[jj + j];
            I[jj + j] = I[kk + k];
            I[kk + k] = tmp;
            k++;
        }
    }

    if(jj > start)
        suffix_split(I, V, start, jj - start, h);

    for (i = 0; i < kk - jj; i++)
        V[I[jj + i]] = kk - 1;
    if (jj == kk - 1)
        I[jj] = -1;

    if (end > kk)
        suffix_split(I, V, kk, end - kk, h);
}

size_t suffix_search(const long long *sfxar,
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
