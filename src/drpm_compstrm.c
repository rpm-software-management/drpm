/*
    Authors:
        Matej Chalk <mchalk@redhat.com>

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

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <zlib.h>
#include <bzlib.h>
#include <lzma.h>
#include <lzlib.h>

struct compstrm {
    unsigned char *data;
    size_t data_len;
    size_t data_pos;
    int filedesc;
    union {
        z_stream gzip;
        bz_stream bzip2;
        lzma_stream lzma;
        struct LZ_Encoder *lzip;
    } stream;
    int (*write_chunk)(struct compstrm *, size_t, const void *);
    int (*finish)(struct compstrm *);
    bool finished;
};

static int finish_bzip2(struct compstrm *);
static int finish_gzip(struct compstrm *);
static int finish_lzip(struct compstrm *);
static int finish_lzma(struct compstrm *);
static int init_bzip2(struct compstrm *, int);
static int init_gzip(struct compstrm *, int);
static int init_lzip(struct compstrm *, int);
static int init_lzma(struct compstrm *, int);
static int init_xz(struct compstrm *, int);
static int writechunk(struct compstrm *, size_t, const void *);
static int writechunk_bzip2(struct compstrm *, size_t, const void *);
static int writechunk_gzip(struct compstrm *, size_t, const void *);
static int writechunk_lzip(struct compstrm *, size_t, const void *);
static int writechunk_lzma(struct compstrm *, size_t, const void *);

static int lzip_error(struct compstrm *strm)
{
    switch (LZ_compress_errno(strm->stream.lzip)) {
    case LZ_ok:
        return DRPM_ERR_OK;
    case LZ_bad_argument:
    case LZ_sequence_error:
        return DRPM_ERR_PROG;
    case LZ_mem_error:
        return DRPM_ERR_MEMORY;
    default:
        return DRPM_ERR_OTHER;
    }
}

int finish_bzip2(struct compstrm *strm)
{
    int error = DRPM_ERR_OK;
    int ret;
    unsigned char *data_tmp;
    char out_buffer[CHUNK_SIZE];
    size_t out_len;

    strm->stream.bzip2.next_in = NULL;
    strm->stream.bzip2.avail_in = 0;

    do {
        strm->stream.bzip2.next_out = out_buffer;
        strm->stream.bzip2.avail_out = CHUNK_SIZE;
        ret = BZ2_bzCompress(&strm->stream.bzip2, BZ_FINISH);
        out_len = CHUNK_SIZE - strm->stream.bzip2.avail_out;
        if (out_len == 0)
            continue;
        if ((data_tmp = realloc(strm->data, strm->data_len + out_len)) == NULL) {
            error = DRPM_ERR_MEMORY;
            goto cleanup;
        }
        strm->data = data_tmp;
        memcpy(strm->data + strm->data_len, out_buffer, out_len);
        strm->data_len += out_len;
    } while (ret != BZ_STREAM_END);

cleanup:
    BZ2_bzCompressEnd(&strm->stream.bzip2);

    return error;
}

int finish_gzip(struct compstrm *strm)
{
    int error = DRPM_ERR_OK;
    unsigned char *data_tmp;
    unsigned char out_buffer[CHUNK_SIZE];
    size_t out_len;

    strm->stream.gzip.next_in = Z_NULL;
    strm->stream.gzip.avail_in = 0;

    do {
        strm->stream.gzip.next_out = out_buffer;
        strm->stream.gzip.avail_out = CHUNK_SIZE;
        deflate(&strm->stream.gzip, Z_FINISH);
        out_len = CHUNK_SIZE - strm->stream.gzip.avail_out;
        if (out_len == 0)
            continue;
        if ((data_tmp = realloc(strm->data, strm->data_len + out_len)) == NULL) {
            error = DRPM_ERR_MEMORY;
            goto cleanup;
        }
        strm->data = data_tmp;
        memcpy(strm->data + strm->data_len, out_buffer, out_len);
        strm->data_len += out_len;
    } while (strm->stream.gzip.avail_out == 0);

cleanup:
    deflateEnd(&strm->stream.gzip);

    return error;
}

int finish_lzma(struct compstrm *strm)
{
    int error = DRPM_ERR_OK;
    int ret;
    unsigned char *data_tmp;
    unsigned char out_buffer[CHUNK_SIZE];
    size_t out_len;

    strm->stream.lzma.next_in = NULL;
    strm->stream.lzma.avail_in = 0;

    do {
        strm->stream.lzma.next_out = out_buffer;
        strm->stream.lzma.avail_out = CHUNK_SIZE;
        switch ((ret = lzma_code(&strm->stream.lzma, LZMA_FINISH))) {
        case LZMA_OK:
        case LZMA_STREAM_END:
            break;
        case LZMA_MEM_ERROR:
            error = DRPM_ERR_MEMORY;
            goto cleanup;
        default:
            error = DRPM_ERR_FORMAT;
            goto cleanup;
        }
        out_len = CHUNK_SIZE - strm->stream.lzma.avail_out;
        if (out_len == 0)
            continue;
        if ((data_tmp = realloc(strm->data, strm->data_len + out_len)) == NULL) {
            error = DRPM_ERR_MEMORY;
            goto cleanup;
        }
        strm->data = data_tmp;
        memcpy(strm->data + strm->data_len, out_buffer, out_len);
        strm->data_len += out_len;
    } while (ret != LZMA_STREAM_END);

cleanup:
    lzma_end(&strm->stream.lzma);

    return error;
}

int finish_lzip(struct compstrm *strm)
{
    int error = DRPM_ERR_OK;
    int rd;
    unsigned char *data_tmp;
    unsigned char out_buffer[CHUNK_SIZE];
    size_t out_len;

    LZ_compress_finish(strm->stream.lzip);

    do {
        if ((rd = LZ_compress_read(strm->stream.lzip, out_buffer, CHUNK_SIZE)) < 0) {
            error = lzip_error(strm);
            if (error == DRPM_ERR_OK)
                error = DRPM_ERR_OTHER;
            goto cleanup;
        }
        out_len = rd;
        if (out_len == 0)
            continue;
        if ((data_tmp = realloc(strm->data, strm->data_len + out_len)) == NULL) {
            error = DRPM_ERR_MEMORY;
            goto cleanup;
        }
        strm->data = data_tmp;
        memcpy(strm->data + strm->data_len, out_buffer, out_len);
        strm->data_len += out_len;
    } while (!LZ_compress_finished(strm->stream.lzip));

cleanup:
    LZ_compress_close(strm->stream.lzip);

    return error;
}

int init_bzip2(struct compstrm *strm, int level)
{
    strm->write_chunk = writechunk_bzip2;
    strm->finish = finish_bzip2;

    strm->stream.bzip2.bzalloc = NULL;
    strm->stream.bzip2.bzfree = NULL;
    strm->stream.bzip2.opaque = NULL;
    strm->stream.bzip2.next_in = NULL;
    strm->stream.bzip2.avail_in = 0;

    if (level == DRPM_COMP_LEVEL_DEFAULT)
        level = 9;

    switch (BZ2_bzCompressInit(&strm->stream.bzip2, level, 0, 0)) {
    case BZ_CONFIG_ERROR:
        BZ2_bzCompressEnd(&strm->stream.bzip2);
        return DRPM_ERR_CONFIG;
    case BZ_MEM_ERROR:
        BZ2_bzCompressEnd(&strm->stream.bzip2);
        return DRPM_ERR_MEMORY;
    }

    return DRPM_ERR_OK;
}

int init_gzip(struct compstrm *strm, int level)
{
    strm->write_chunk = writechunk_gzip;
    strm->finish = finish_gzip;

    strm->stream.gzip.zalloc = Z_NULL;
    strm->stream.gzip.zfree = Z_NULL;
    strm->stream.gzip.opaque = Z_NULL;

    if (level == DRPM_COMP_LEVEL_DEFAULT)
        level = Z_BEST_COMPRESSION;

    switch (deflateInit2(&strm->stream.gzip, level, Z_DEFLATED,
            16 + MAX_WBITS, 8, Z_DEFAULT_STRATEGY)) {
    case Z_VERSION_ERROR:
        deflateEnd(&strm->stream.gzip);
        return DRPM_ERR_CONFIG;
    case Z_MEM_ERROR:
        deflateEnd(&strm->stream.gzip);
        return DRPM_ERR_MEMORY;
    }

    return DRPM_ERR_OK;
}

int init_lzma(struct compstrm *strm, int level)
{
    lzma_stream stream = LZMA_STREAM_INIT;
    lzma_options_lzma options;

    strm->write_chunk = writechunk_lzma;
    strm->finish = finish_lzma;
    strm->stream.lzma = stream;

    if (level == DRPM_COMP_LEVEL_DEFAULT)
        level = 2;

    lzma_lzma_preset(&options, level);

    switch (lzma_alone_encoder(&strm->stream.lzma, &options)) {
    case LZMA_OK:
        break;
    case LZMA_MEM_ERROR:
        return DRPM_ERR_MEMORY;
    default:
        return DRPM_ERR_FORMAT;
    }

    return DRPM_ERR_OK;
}

int init_xz(struct compstrm *strm, int level)
{
    lzma_stream stream = LZMA_STREAM_INIT;

    strm->write_chunk = writechunk_lzma;
    strm->finish = finish_lzma;
    strm->stream.lzma = stream;

    if (level == DRPM_COMP_LEVEL_DEFAULT)
        level = 3;

    switch (lzma_easy_encoder(&strm->stream.lzma, level, LZMA_CHECK_SHA256)) {
    case LZMA_OK:
        break;
    case LZMA_MEM_ERROR:
        return DRPM_ERR_MEMORY;
    default:
        return DRPM_ERR_FORMAT;
    }

    return DRPM_ERR_OK;
}

int init_lzip(struct compstrm *strm, int level)
{
    int error;

    strm->write_chunk = writechunk_lzip;
    strm->finish = finish_lzip;

    if ((strm->stream.lzip = LZ_compress_open(65535, 16, SIZE_MAX)) == NULL)
        return DRPM_ERR_MEMORY;

    if ((error = lzip_error(strm)) != DRPM_ERR_OK)
        LZ_compress_close(strm->stream.lzip);

    return error;
}

int compstrm_destroy(struct compstrm **strm)
{
    if (strm == NULL || *strm == NULL)
        return DRPM_ERR_PROG;

    free((*strm)->data);
    free(*strm);
    *strm = NULL;

    return DRPM_ERR_OK;
}

int compstrm_init(struct compstrm **strm, int filedesc, unsigned short comp, int level)
{
    int error;

    if (strm == NULL || (level != DRPM_COMP_LEVEL_DEFAULT && (level < 1 || level > 9)))
        return DRPM_ERR_PROG;

    if ((*strm = malloc(sizeof(struct compstrm))) == NULL)
        return DRPM_ERR_MEMORY;

    (*strm)->data = NULL;
    (*strm)->data_len = 0;
    (*strm)->data_pos = 0;
    (*strm)->filedesc = filedesc;
    (*strm)->finished = false;

    switch (comp) {
    case DRPM_COMP_NONE:
        (*strm)->write_chunk = writechunk;
        (*strm)->finish = NULL;
        break;
    case DRPM_COMP_GZIP:
        if ((error = init_gzip(*strm, level)) != DRPM_ERR_OK)
            goto cleanup_fail;
        break;
    case DRPM_COMP_BZIP2:
        if ((error = init_bzip2(*strm, level)) != DRPM_ERR_OK)
            goto cleanup_fail;
        break;
    case DRPM_COMP_LZMA:
        if ((error = init_lzma(*strm, level)) != DRPM_ERR_OK)
            goto cleanup_fail;
        break;
    case DRPM_COMP_XZ:
        if ((error = init_xz(*strm, level)) != DRPM_ERR_OK)
            goto cleanup_fail;
        break;
    case DRPM_COMP_LZIP:
        if ((error = init_lzip(*strm, level)) != DRPM_ERR_OK)
            goto cleanup_fail;
        break;
    default:
        return DRPM_ERR_PROG;
    }

    return DRPM_ERR_OK;

cleanup_fail:
    free(*strm);
    *strm = NULL;

    return error;
}

int compstrm_finish(struct compstrm *strm, unsigned char **data, size_t *data_len)
{
    int error;
    size_t comp_write_len;
    const bool copy_data = (data != NULL && data_len != NULL);

    if (strm == NULL || strm->finished)
        return DRPM_ERR_PROG;

    if (copy_data) {
        *data = NULL;
        *data_len = 0;
    }

    if (strm->finish != NULL) {
        if ((error = strm->finish(strm)) != DRPM_ERR_OK)
            return error;
        comp_write_len = strm->data_len - strm->data_pos;
        if (strm->filedesc >= 0 && comp_write_len > 0 &&
            write(strm->filedesc, strm->data + strm->data_pos,
                  comp_write_len) != (ssize_t)comp_write_len)
                return DRPM_ERR_IO;
    }

    strm->finished = true;

    if (copy_data && strm->data_len > 0) {
        if ((*data = malloc(strm->data_len)) == NULL)
            return DRPM_ERR_MEMORY;
        memcpy(*data, strm->data, strm->data_len);
        *data_len = strm->data_len;
    }

    return DRPM_ERR_OK;
}

int compstrm_write_be32(struct compstrm *strm, uint32_t number)
{
    unsigned char bytes[4];

    if (strm == NULL || strm->finished)
        return DRPM_ERR_PROG;

    create_be32(number, bytes);

    return compstrm_write(strm, 4, bytes);
}

int compstrm_write_be64(struct compstrm *strm, uint64_t number)
{
    unsigned char bytes[8];

    if (strm == NULL || strm->finished)
        return DRPM_ERR_PROG;

    create_be64(number, bytes);

    return compstrm_write(strm, 8, bytes);
}

int compstrm_write(struct compstrm *strm, size_t write_len, const void *buffer)
{
    int error;
    size_t comp_write_len;

    if (strm == NULL || strm->finished)
        return DRPM_ERR_PROG;

    if (write_len == 0)
        return DRPM_ERR_OK;

    if (buffer == NULL)
        return DRPM_ERR_PROG;

    if ((error = strm->write_chunk(strm, write_len, buffer)) != DRPM_ERR_OK)
        return error;

    comp_write_len = strm->data_len - strm->data_pos;

    if (strm->filedesc >= 0 && comp_write_len > 0) {
        if (write(strm->filedesc, strm->data + strm->data_pos,
                  comp_write_len) != (ssize_t)comp_write_len)
            return DRPM_ERR_IO;
    }

    strm->data_pos = strm->data_len;

    return DRPM_ERR_OK;
}

int writechunk(struct compstrm *strm, size_t in_len, const void *in_buffer)
{
    unsigned char *data_tmp;

    if ((data_tmp = realloc(strm->data, strm->data_len + in_len)) == NULL)
        return DRPM_ERR_MEMORY;

    strm->data = data_tmp;
    memcpy(strm->data + strm->data_len, in_buffer, in_len);
    strm->data_len += in_len;

    return DRPM_ERR_OK;
}

int writechunk_bzip2(struct compstrm *strm, size_t in_len, const void *in_buffer)
{
    unsigned char *data_tmp;
    char out_buffer[CHUNK_SIZE];
    size_t out_len;

    strm->stream.bzip2.next_in = (char *)in_buffer;
    strm->stream.bzip2.avail_in = in_len;

    do {
        strm->stream.bzip2.next_out = out_buffer;
        strm->stream.bzip2.avail_out = CHUNK_SIZE;
        BZ2_bzCompress(&strm->stream.bzip2, BZ_RUN);
        out_len = CHUNK_SIZE - strm->stream.bzip2.avail_out;
        if (out_len == 0)
            continue;
        if ((data_tmp = realloc(strm->data, strm->data_len + out_len)) == NULL)
            return DRPM_ERR_MEMORY;
        strm->data = data_tmp;
        memcpy(strm->data + strm->data_len, out_buffer, out_len);
        strm->data_len += out_len;
    } while (strm->stream.bzip2.avail_out == 0);

    return DRPM_ERR_OK;
}

int writechunk_gzip(struct compstrm *strm, size_t in_len, const void *in_buffer)
{
    unsigned char *data_tmp;
    unsigned char out_buffer[CHUNK_SIZE];
    size_t out_len;

    strm->stream.gzip.next_in = (unsigned char *)in_buffer;
    strm->stream.gzip.avail_in = in_len;

    do {
        strm->stream.gzip.next_out = out_buffer;
        strm->stream.gzip.avail_out = CHUNK_SIZE;
        deflate(&strm->stream.gzip, Z_NO_FLUSH);
        out_len = CHUNK_SIZE - strm->stream.gzip.avail_out;
        if (out_len == 0)
            continue;
        if ((data_tmp = realloc(strm->data, strm->data_len + out_len)) == NULL)
            return DRPM_ERR_MEMORY;
        strm->data = data_tmp;
        memcpy(strm->data + strm->data_len, out_buffer, out_len);
        strm->data_len += out_len;
    } while (strm->stream.gzip.avail_out == 0);

    return DRPM_ERR_OK;
}

int writechunk_lzma(struct compstrm *strm, size_t in_len, const void *in_buffer)
{
    unsigned char *data_tmp;
    unsigned char out_buffer[CHUNK_SIZE];
    size_t out_len;

    strm->stream.lzma.next_in = (unsigned char *)in_buffer;
    strm->stream.lzma.avail_in = in_len;

    do {
        strm->stream.lzma.next_out = out_buffer;
        strm->stream.lzma.avail_out = CHUNK_SIZE;
        switch (lzma_code(&strm->stream.lzma, LZMA_RUN)) {
        case LZMA_OK:
            break;
        case LZMA_MEM_ERROR:
            return DRPM_ERR_MEMORY;
        default:
            return DRPM_ERR_FORMAT;
        }
        out_len = CHUNK_SIZE - strm->stream.lzma.avail_out;
        if (out_len == 0)
            continue;
        if ((data_tmp = realloc(strm->data, strm->data_len + out_len)) == NULL)
            return DRPM_ERR_MEMORY;
        strm->data = data_tmp;
        memcpy(strm->data + strm->data_len, out_buffer, out_len);
        strm->data_len += out_len;
    } while (strm->stream.lzma.avail_out == 0);

    return DRPM_ERR_OK;
}

int writechunk_lzip(struct compstrm *strm, size_t in_len, const void *in_buffer)
{
    int error;
    unsigned char *data_tmp;
    unsigned char out_buffer[CHUNK_SIZE];
    size_t out_len;
    size_t written = 0;
    int wr;
    int rd;

    while (written < in_len) {
        if (LZ_compress_write_size(strm->stream.lzip) > 0) {
            if ((wr = LZ_compress_write(strm->stream.lzip,
                                        (unsigned char *)in_buffer + written,
                                        in_len - written)) < 0) {
                error = lzip_error(strm);
                return error == DRPM_ERR_OK ? DRPM_ERR_OTHER : error;
            }
            written += wr;
        }
        if ((rd = LZ_compress_read(strm->stream.lzip, out_buffer, CHUNK_SIZE)) < 0) {
            error = lzip_error(strm);
            return error == DRPM_ERR_OK ? DRPM_ERR_OTHER : error;
        }
        out_len = rd;
        if (out_len == 0)
            continue;
        if ((data_tmp = realloc(strm->data, strm->data_len + out_len)) == NULL)
            return DRPM_ERR_MEMORY;
        strm->data = data_tmp;
        memcpy(strm->data + strm->data_len, out_buffer, out_len);
        strm->data_len += out_len;
    };

    return DRPM_ERR_OK;
}
