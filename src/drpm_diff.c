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

/* Compares <old> and <new> byte sequences (of lengths <old_len>
 * and <new_len>, respectively).
 * If neither <add_block_ret> nor <add_block_len_ret> are NULL,
 * creates an add block and stores it in <*add_block_ret>
 * (and its length in <*add_block_len_ret>). The addblock compression
 * is determined by <add_block_comp> and <add_block_comp_level>.
 * Internal data will be created as chunks in an array and stored in
 * <*int_data_array_ret> (length in <*int_data_array_len_ret>).
 * External copies will be stored in <*ext_copies_ret> and the number
 * of external copies shall be in <*ext_copies_count_ret>.
 * Internal copies will be stored in <*int_copies_ret> and the number
 * of internal copies shall be in <*int_copies_count_ret>. */
int make_diff(const unsigned char *old, size_t old_len,
              const unsigned char *new, size_t new_len,
              const unsigned char ***int_data_array_ret, uint64_t *int_data_len_ret,
              uint32_t **ext_copies_ret, uint32_t *ext_copies_count_ret,
              uint32_t **int_copies_ret, uint32_t *int_copies_count_ret,
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
        ext_copies_ret == NULL || ext_copies_count_ret == NULL ||
        int_copies_ret == NULL || int_copies_count_ret == NULL)
        return DRPM_ERR_PROG;

    if (addblk)
        *add_block_ret = NULL;

    //if ((error = sfxsrt_create(&suffix, old, old_len)) != DRPM_ERR_OK)
    if ((error = hash_create(&hashtab, old, old_len)) != DRPM_ERR_OK)
        goto cleanup_fail;

    if (addblk && (error = compstrm_init(&stream, -1, add_block_comp, add_block_comp_level)) != DRPM_ERR_OK)
        goto cleanup_fail;

    while (new_pos_prev < new_len) {
        /* find new match */
        //new_pos = sfxsrt_search(suffix, old, old_len, new, new_len,
        new_pos = hash_search(hashtab, old, old_len, new, new_len,
                              addblk ? old_pos_prev - new_pos_prev : old_len,
                              new_pos + len, &old_pos, &len);

        /* extend last match forwards */
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
            // no add block => no mismatches
            for (i = 0; i < max_len; i++)
                if (old[old_pos_prev + i] != new[new_pos_prev + i])
                    break;
            len_forward = i;
        }

        /* extend new match backwards */
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
            // no add block => no mismatches
            len_back = 0;
        }

        /* if extensions overlap, find a good place to split */
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

        /*

             old_off, old_len
                |--------->
        old: B6 00 00 57 5E 71 0C 04 02 17 B5 BE 15 43 A7 B0 00 00
                >>>>>>>>>>>                <<<<< ==============

                   00 00 0C F3 -> add block

                      >>>>>>>>>>>       <<<<< ==============
        new: 13 10 24 00 00 63 51 25 C1 B5 1D 15 43 A7 B0 00 4F 92
                                  |--->
                             new_off, new_len

        >>> - forwards extension of previous match
        <<< - backwards extension of new match
        === - new match

         */

        if (!resize32((void **)&diff_copies, diff_copies_len, sizeof(struct diff_copy))) {
            error = DRPM_ERR_MEMORY;
            goto cleanup;
        }

        diff_copies[diff_copies_len].new_off = new_pos_prev + len_forward;
        diff_copies[diff_copies_len].new_len = (new_pos - len_back) - (new_pos_prev + len_forward);
        diff_copies[diff_copies_len].old_off = old_pos_prev;
        diff_copies[diff_copies_len].old_len = len_forward;
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

    /* use diff_copies to create outputs */
    if ((error = create_diff_copies(diff_copies, diff_copies_len, ext_copies_ret, ext_copies_count_ret,
                                    int_copies_ret, int_copies_count_ret)) != DRPM_ERR_OK ||
        (error = create_int_data_array(diff_copies, new, *int_copies_ret, *int_copies_count_ret,
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

/* Creates internal and external copies from diff data. */
int create_diff_copies(const struct diff_copy *diff_copies, size_t diff_copies_len,
                       uint32_t **ext_copies_ret, uint32_t *ext_copies_count_ret,
                       uint32_t **int_copies_ret, uint32_t *int_copies_count_ret)
{
    int error;

    uint32_t *int_copies = NULL;
    uint32_t int_copies_count = 0;
    uint32_t *ext_copies = NULL;
    uint32_t ext_copies_count = 0;

    size_t new_len;
    size_t old_len;
    size_t old_off;

    uint32_t last_ext_copies_count = 0;
    size_t offset = 0;

    for (size_t i = 0; i < diff_copies_len; i++) {
        new_len = diff_copies[i].new_len;
        old_len = diff_copies[i].old_len;
        old_off = diff_copies[i].old_off;

        if (old_len) {
            while (true) {
                if (!resize16((void **)&ext_copies, ext_copies_count * 2, 4)) {
                    error = DRPM_ERR_MEMORY;
                    goto cleanup_fail;
                }

                if (old_off > offset && old_off - offset >= (uint32_t)INT32_MIN) {
                    ext_copies[ext_copies_count * 2] = INT32_MAX;
                    ext_copies[ext_copies_count * 2 + 1] = 0;
                    ext_copies_count++;
                    offset += INT32_MAX;
                    continue;
                } else if (old_off < offset && offset - old_off >= (uint32_t)INT32_MIN) {
                    ext_copies[ext_copies_count * 2] = TWOS_COMPLEMENT(INT32_MAX);
                    ext_copies[ext_copies_count * 2 + 1] = 0;
                    ext_copies_count++;
                    offset -= INT32_MAX;
                    continue;
                }

                ext_copies[ext_copies_count * 2] = (int32_t)(old_off - offset);

                if (old_len >= (uint32_t)INT32_MIN) {
                    ext_copies[ext_copies_count++ * 2 + 1] = INT32_MAX;
                    old_len -= INT32_MAX;
                    old_off = offset += INT32_MAX;
                    continue;
                }

                ext_copies[ext_copies_count++ * 2 + 1] = old_len;
                offset = old_off + old_len;
                break;
            }
        }

        if (new_len) {
            while (true) {
                if (!resize16((void **)&int_copies, int_copies_count * 2, 4)) {
                    error = DRPM_ERR_MEMORY;
                    goto cleanup_fail;
                }

                int_copies[int_copies_count * 2] = ext_copies_count - last_ext_copies_count;
                last_ext_copies_count = ext_copies_count;

                if (new_len >= (uint32_t)INT32_MIN) {
                    int_copies[int_copies_count++ * 2 + 1] = INT32_MAX;
                    new_len -= INT32_MAX;
                    continue;
                }

                int_copies[int_copies_count++ * 2 + 1] = new_len;
                break;
            }
        }
    }

    if (ext_copies_count - last_ext_copies_count > 0) {
        if (!resize16((void **)&int_copies, int_copies_count * 2, 4)) {
            error = DRPM_ERR_MEMORY;
            goto cleanup_fail;
        }
        int_copies[int_copies_count * 2] = ext_copies_count - last_ext_copies_count;
        int_copies[int_copies_count * 2 + 1] = 0;
        int_copies_count++;
    }

    *ext_copies_ret = ext_copies;
    *ext_copies_count_ret = ext_copies_count;
    *int_copies_ret = int_copies;
    *int_copies_count_ret = int_copies_count;

    return DRPM_ERR_OK;

cleanup_fail:
    free(int_copies);
    free(ext_copies);

    return error;
}

/* Constructs internal data from diff data and internal copies. */
int create_int_data_array(const struct diff_copy *diff_copies, //size_t diff_copies_len,
                          const unsigned char *new,
                          const uint32_t *int_copies, uint32_t int_copies_count,
                          const unsigned char ***int_data_array_ret, uint64_t *int_data_len_ret)
{
    const unsigned char **int_data_array;
    uint64_t int_data_len = 0;
    size_t todo;
    size_t offset = 0;
    size_t left = 0;

    if ((int_data_array = malloc(int_copies_count * sizeof(unsigned char *))) == NULL)
        return DRPM_ERR_MEMORY;

    for (size_t i = 0, j = 0; i < int_copies_count; i++) {
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
