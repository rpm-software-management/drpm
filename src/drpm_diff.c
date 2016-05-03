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
#include <stdbool.h>

#define BUFFER_SIZE 4096

struct diff_copy {
    size_t old_off;
    size_t old_len;
    size_t new_off;
    size_t new_len;
};

static int create_diff_copies(const struct diff_copy *, size_t,
                              uint32_t **, uint32_t *, uint32_t **, uint32_t *);
static int create_int_data_array(const struct diff_copy *, const unsigned char *,
                                 const uint32_t *, uint32_t,
                                 const unsigned char ***, uint64_t *);

int make_diff(const unsigned char *old, size_t old_len,
              const unsigned char *new, size_t new_len,
              const unsigned char ***int_data_array_ret, uint64_t *int_data_len_ret,
              uint32_t **ext_copies_ret, uint32_t *ext_copies_size_ret,
              uint32_t **int_copies_ret, uint32_t *int_copies_size_ret,
              unsigned char **add_block_ret, uint32_t *add_block_len_ret,
              unsigned short add_block_comp, int add_block_comp_level)
{
    int error;

    const bool addblk = (add_block_ret != NULL && add_block_len_ret != NULL);
    size_t add_block_len;
    struct compstrm *stream;

    struct diff_copy *diff_copies = NULL;
    size_t diff_copies_len = 0;

    //struct sfxsrt *suffix;
    struct hash *hashtab;

    size_t old_pos = 0;
    size_t new_pos = 0;
    size_t old_pos_prev = 0;
    size_t new_pos_prev = 0;

    size_t len = 0;
    size_t len_forward;
    size_t len_back;
    size_t len_overlap;
    size_t len_split;

    size_t max_len;
    size_t i;
    size_t count;
    size_t best_count;
    size_t count_back;
    size_t count_forward;

    unsigned char buffer[BUFFER_SIZE];
    size_t write_len;

    if (old == NULL || new == NULL ||
        int_data_array_ret == NULL || int_data_len_ret == NULL ||
        ext_copies_ret == NULL || ext_copies_size_ret == NULL ||
        int_copies_ret == NULL || int_copies_size_ret == NULL)
        return DRPM_ERR_PROG;

    if (addblk)
        *add_block_ret = NULL;

    //if ((error = sfxsrt_create(&suffix, old, old_len)) != DRPM_ERR_OK)
    if ((error = hash_create(&hashtab, old, old_len)) != DRPM_ERR_OK)
        goto cleanup_fail;

    if (addblk && (error = compstrm_init(&stream, -1, add_block_comp, add_block_comp_level)) != DRPM_ERR_OK)
        goto cleanup_fail;

    while (new_pos_prev < new_len) {
        //new_pos = sfxsrt_search(suffix, old, old_len, new, new_len,
        new_pos = hash_search(hashtab, old, old_len, new, new_len,
                              addblk ? old_pos_prev - new_pos_prev : old_len,
                              new_pos + len, &old_pos, &len);

        //printf("old_pos = %04zx, new_pos = %04zx, len = %04zx\n", old_pos, new_pos, len);

        max_len = MIN(old_len - old_pos_prev, new_pos - new_pos_prev);
        if (addblk) {
            len_forward = best_count = count = 0;
            for (i = 0; i < max_len; ) {
                if (old[old_pos_prev + i] == new[new_pos_prev + i]) {
                    count++;
                    i++;
                    if (2 * count >= best_count + i) {
                        best_count = 2 * count - i;
                        len_forward = i;
                    }
                } else {
                    i++;
                }
            }
        } else {
            for (i = 0; i < max_len; i++)
                if (old[old_pos_prev + i] != new[new_pos_prev + i])
                    break;
            len_forward = i;
        }

        if (addblk && new_pos < new_len) {
            len_back = best_count = count = 0;
            max_len = MIN(old_pos, new_pos - new_pos_prev);
            for (i = 1; i <= max_len; i++) {
                if (old[old_pos - i] == new[new_pos - i]) {
                    count++;
                    if (2 * count >= best_count + i) {
                        best_count = 2 * count - i;
                        len_back = i;
                    }
                }
            }
        } else {
            len_back = 0;
        }

        if (new_pos_prev + len_forward > new_pos - len_back) {
            len_split = best_count = count_back = count_forward = 0;
            len_overlap = (new_pos_prev + len_forward) - (new_pos - len_back);
            for (i = 0; i < len_overlap; i++) {
                if (old[old_pos_prev + len_forward - len_overlap + i] ==
                    new[new_pos_prev + len_forward - len_overlap + i])
                    count_forward++;
                if (old[old_pos - len_back + i] == new[new_pos - len_back + i])
                    count_back++;
                if (count_forward > count_back && count_forward - count_back > best_count) {
                    best_count = count_forward - count_back;
                    len_split = i + 1;
                }
            }
            len_forward -= len_overlap - len_split;
            len_back -= len_split;
        }

        if (!resize32((void **)&diff_copies, diff_copies_len, sizeof(struct diff_copy))) {
            error = DRPM_ERR_MEMORY;
            goto cleanup;
        }

        diff_copies[diff_copies_len].new_off = new_pos_prev + len_forward;
        diff_copies[diff_copies_len].new_len = (new_pos - len_back) - (new_pos_prev + len_forward);
        diff_copies[diff_copies_len].old_off = old_pos_prev;
        diff_copies[diff_copies_len].old_len = len_forward;
        //printf("[%02zx] %04zx %04zx %04zx %04zx\n", diff_copies_len, diff_copies[diff_copies_len].new_off, diff_copies[diff_copies_len].new_len, diff_copies[diff_copies_len].old_off, diff_copies[diff_copies_len].old_len);
        diff_copies_len++;

        if (addblk) {
            while (len_forward > 0) {
                write_len = MIN(len_forward, BUFFER_SIZE);
                for (i = 0; i < write_len; i++)
                    buffer[i] = new[new_pos_prev + i] - old[old_pos_prev + i];
                if ((error = compstrm_write(stream, write_len, buffer)) != DRPM_ERR_OK)
                    goto cleanup_fail;
                old_pos_prev += write_len;
                new_pos_prev += write_len;
                len_forward -= write_len;
            }
        }

        old_pos_prev = old_pos - len_back;
        new_pos_prev = new_pos - len_back;
    }

    if ((error = create_diff_copies(diff_copies, diff_copies_len, ext_copies_ret, ext_copies_size_ret,
                                    int_copies_ret, int_copies_size_ret)) != DRPM_ERR_OK ||
        (error = create_int_data_array(diff_copies, new, *int_copies_ret, *int_copies_size_ret,
                                       int_data_array_ret, int_data_len_ret)) != DRPM_ERR_OK ||
        (addblk && (error = compstrm_finish(stream, add_block_ret, &add_block_len)) != DRPM_ERR_OK))
        goto cleanup_fail;

    if (addblk)
        *add_block_len_ret = add_block_len;

    goto cleanup;

cleanup_fail:
    if (addblk)
        free(*add_block_ret);

cleanup:
    free(diff_copies);
    //sfxsrt_free(&suffix);
    hash_free(&hashtab);

    if (addblk) {
        if (error == DRPM_ERR_OK)
            error = compstrm_destroy(&stream);
        else
            compstrm_destroy(&stream);
    }

    return error;
}

int create_diff_copies(const struct diff_copy *diff_copies, size_t diff_copies_len,
                       uint32_t **ext_copies_ret, uint32_t *ext_copies_size_ret,
                       uint32_t **int_copies_ret, uint32_t *int_copies_size_ret)
{
    int error;

    uint32_t *in = NULL;
    uint32_t inn = 0;
    uint32_t *out = NULL;
    uint32_t outn = 0;

    size_t new_len;
    size_t old_len;
    size_t old_off;

    uint32_t last_outn = 0;
    size_t offset = 0;

    for (size_t i = 0; i < diff_copies_len; i++) {
        new_len = diff_copies[i].new_len;
        old_len = diff_copies[i].old_len;
        old_off = diff_copies[i].old_off;

        if (old_len) {
            while (true) {
                if (!resize16((void **)&out, outn * 2, 4)) {
                    error = DRPM_ERR_MEMORY;
                    goto cleanup_fail;
                }

                if (old_off > offset && old_off - offset >= (uint32_t)INT32_MIN) {
                    out[outn * 2] = INT32_MAX;
                    out[outn * 2 + 1] = 0;
                    outn++;
                    offset += INT32_MAX;
                    continue;
                } else if (old_off < offset && offset - old_off >= (uint32_t)INT32_MIN) {
                    out[outn * 2] = TWOS_COMPLEMENT(INT32_MAX);
                    out[outn * 2 + 1] = 0;
                    outn++;
                    offset -= INT32_MAX;
                    continue;
                }

                out[outn * 2] = (int32_t)(old_off - offset);

                if (old_len >= (uint32_t)INT32_MIN) {
                    out[outn++ * 2 + 1] = INT32_MAX;
                    old_len -= INT32_MAX;
                    old_off = offset += INT32_MAX;
                    continue;
                }

                out[outn++ * 2 + 1] = old_len;
                offset = old_off + old_len;
                break;
            }
        }

        if (new_len) {
            while (true) {
                if (!resize16((void **)&in, inn * 2, 4)) {
                    error = DRPM_ERR_MEMORY;
                    goto cleanup_fail;
                }

                in[inn * 2] = outn - last_outn;
                last_outn = outn;

                if (new_len >= (uint32_t)INT32_MIN) {
                    in[inn++ * 2 + 1] = INT32_MAX;
                    new_len -= INT32_MAX;
                    continue;
                }

                in[inn++ * 2 + 1] = new_len;
                break;
            }
        }
    }

    if (outn - last_outn > 0) {
        if (!resize16((void **)&in, inn * 2, 4)) {
            error = DRPM_ERR_MEMORY;
            goto cleanup_fail;
        }
        in[inn * 2] = outn - last_outn;
        in[inn * 2 + 1] = 0;
        inn++;
    }

    *ext_copies_ret = out;
    *ext_copies_size_ret = outn;
    *int_copies_ret = in;
    *int_copies_size_ret = inn;

    return DRPM_ERR_OK;

cleanup_fail:
    free(in);
    free(out);

    return error;
}

int create_int_data_array(const struct diff_copy *diff_copies, //size_t diff_copies_len,
                          const unsigned char *new,
                          const uint32_t *int_copies, uint32_t int_copies_size,
                          const unsigned char ***int_data_array_ret, uint64_t *int_data_len_ret)
{
    const unsigned char **int_data_array;
    uint64_t int_data_len = 0;
    size_t todo;
    size_t offset = 0;
    size_t left = 0;

    if ((int_data_array = malloc(int_copies_size * sizeof(unsigned char *))) == NULL)
        return DRPM_ERR_MEMORY;

    for (size_t i = 0, j = 0; i < int_copies_size; i++) {
        todo = int_copies[i * 2 + 1];
        if (todo > 0) {
            while (left == 0) {
                left = diff_copies[j].new_len;
                offset = diff_copies[j].new_off;
                j++;
            }
        }
        int_data_array[i] = new + offset;
        offset += todo;
        left -= todo;
        int_data_len += todo;
    }

    *int_data_array_ret = int_data_array;
    *int_data_len_ret = int_data_len;

    return DRPM_ERR_OK;
}
