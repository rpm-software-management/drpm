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
#include <unistd.h>
#include <fcntl.h>
#include <zlib.h>
#include <bzlib.h>
#include <lzma.h>

#define MAGIC_BZIP2(x) (((x) >> 40) == 0x425A68)
#define MAGIC_GZIP(x) (((x) >> 48) == 0x1F8B)
#define MAGIC_LZMA(x) (((x) >> 40) == 0x5D0000)
#define MAGIC_XZ(x) (((x) >> 16) == 0xFD377A585A00)

struct decompstrm {
    char *data;
    size_t data_len;
    size_t data_pos;
    int filedesc;
    union {
        z_stream gzip;
        bz_stream bzip2;
        lzma_stream lzma;
    } stream;
    int (*read_chunk)(struct decompstrm *);
    void (*finish)(struct decompstrm *);
    size_t read_len;
};

static void finish_bzip2(struct decompstrm *);
static void finish_gzip(struct decompstrm *);
static void finish_lzma(struct decompstrm *);
static int init_bzip2(struct decompstrm *);
static int init_gzip(struct decompstrm *);
static int init_lzma(struct decompstrm *);
static int readchunk(struct decompstrm *);
static int readchunk_bzip2(struct decompstrm *);
static int readchunk_gzip(struct decompstrm *);
static int readchunk_lzma(struct decompstrm *);

void finish_bzip2(struct decompstrm *strm)
{
    BZ2_bzDecompressEnd(&strm->stream.bzip2);
}

void finish_gzip(struct decompstrm *strm)
{
    inflateEnd(&strm->stream.gzip);
}

void finish_lzma(struct decompstrm *strm)
{
    lzma_end(&strm->stream.lzma);
}

int init_bzip2(struct decompstrm *strm)
{
    strm->read_chunk = readchunk_bzip2;
    strm->finish = finish_bzip2;
    strm->stream.bzip2.bzalloc = NULL;
    strm->stream.bzip2.bzfree = NULL;
    strm->stream.bzip2.opaque = NULL;
    strm->stream.bzip2.next_in = NULL;
    strm->stream.bzip2.avail_in = 0;

    switch (BZ2_bzDecompressInit(&strm->stream.bzip2, 0, 1)) {
    case BZ_CONFIG_ERROR:
        BZ2_bzDecompressEnd(&strm->stream.bzip2);
        return DRPM_ERR_CONFIG;
    case BZ_MEM_ERROR:
        BZ2_bzDecompressEnd(&strm->stream.bzip2);
        return DRPM_ERR_MEMORY;
    }

    return DRPM_ERR_OK;
}

int init_gzip(struct decompstrm *strm)
{
    strm->read_chunk = readchunk_gzip;
    strm->finish = finish_gzip;
    strm->stream.gzip.zalloc = Z_NULL;
    strm->stream.gzip.zfree = Z_NULL;
    strm->stream.gzip.opaque = Z_NULL;
    strm->stream.gzip.next_in = Z_NULL;
    strm->stream.gzip.avail_in = 0;

    switch (inflateInit2(&strm->stream.gzip, 16 + MAX_WBITS)) {
    case Z_VERSION_ERROR:
        inflateEnd(&strm->stream.gzip);
        return DRPM_ERR_CONFIG;
    case Z_MEM_ERROR:
        inflateEnd(&strm->stream.gzip);
        return DRPM_ERR_MEMORY;
    }

    return DRPM_ERR_OK;
}

int init_lzma(struct decompstrm *strm)
{
    lzma_stream stream = LZMA_STREAM_INIT;

    strm->read_chunk = readchunk_lzma;
    strm->finish = finish_lzma;
    strm->stream.lzma = stream;

    switch (lzma_auto_decoder(&strm->stream.lzma, UINT64_MAX, 0)) {
    case LZMA_OK:
        break;
    case LZMA_MEM_ERROR:
        return DRPM_ERR_MEMORY;
    default:
        return DRPM_ERR_FORMAT;
    }

    return DRPM_ERR_OK;
}

int decompstrm_destroy(struct decompstrm **strm)
{
    if (strm == NULL || *strm == NULL)
        return DRPM_ERR_ARGS;

    if ((*strm)->finish != NULL)
        (*strm)->finish(*strm);

    free((*strm)->data);
    free(*strm);
    *strm = NULL;

    return DRPM_ERR_OK;
}

int decompstrm_init(struct decompstrm **strm, int filedesc, uint32_t *comp)
{
    uint64_t magic;
    int error;

    if (strm == NULL || filedesc < 0)
        return DRPM_ERR_ARGS;

    if ((error = read_be64(filedesc, &magic)) != DRPM_ERR_OK)
        return error;

    if (lseek(filedesc, -8, SEEK_CUR) == -1)
        return DRPM_ERR_IO;

    if ((*strm = malloc(sizeof(struct decompstrm))) == NULL)
        return DRPM_ERR_MEMORY;

    (*strm)->data = NULL;
    (*strm)->data_len = 0;
    (*strm)->data_pos = 0;
    (*strm)->filedesc = filedesc;
    (*strm)->read_len = 0;

    if (MAGIC_GZIP(magic)) {
        if (comp != NULL)
            *comp = DRPM_COMP_GZIP;
        return init_gzip(*strm);
    } else if (MAGIC_BZIP2(magic)) {
        if (comp != NULL)
            *comp = DRPM_COMP_BZIP2;
        return init_bzip2(*strm);
    } else if (MAGIC_XZ(magic)) {
        if (comp != NULL)
            *comp = DRPM_COMP_XZ;
        return init_lzma(*strm);
    } else if (MAGIC_LZMA(magic)) {
        if (comp != NULL)
            *comp = DRPM_COMP_LZMA;
        return init_lzma(*strm);
    }

    if (comp != NULL)
        *comp = DRPM_COMP_NONE;

    (*strm)->read_chunk = readchunk;
    (*strm)->finish = NULL;

    return DRPM_ERR_OK;
}

int decompstrm_copy_read_len(struct decompstrm *strm, size_t *read_len)
{
    if (strm == NULL || read_len == NULL)
        return DRPM_ERR_ARGS;

    *read_len = strm->read_len;

    return DRPM_ERR_OK;
}

int decompstrm_read_be32(struct decompstrm *strm, uint32_t *buffer_ret)
{
    int error;
    char bytes[4];

    if (strm == NULL)
        return DRPM_ERR_ARGS;

    if ((error = decompstrm_read(strm, 4, bytes)) != DRPM_ERR_OK)
        return error;

    *buffer_ret = parse_be32(bytes);

    return DRPM_ERR_OK;
}

int decompstrm_read_be64(struct decompstrm *strm, uint64_t *buffer_ret)
{
    int error;
    char bytes[8];

    if (strm == NULL)
        return DRPM_ERR_ARGS;

    if ((error = decompstrm_read(strm, 8, bytes)) != DRPM_ERR_OK)
        return error;

    *buffer_ret = parse_be64(bytes);

    return DRPM_ERR_OK;
}

int decompstrm_read(struct decompstrm *strm, size_t read_len, char *buffer_ret)
{
    int error;

    if (strm == NULL)
        return DRPM_ERR_ARGS;

    while (strm->data_pos + read_len > strm->data_len)
        if ((error = strm->read_chunk(strm)) != DRPM_ERR_OK)
            return error;

    if (buffer_ret != NULL)
        memcpy(buffer_ret, strm->data + strm->data_pos, read_len);

    strm->data_pos += read_len;

    return DRPM_ERR_OK;
}

int decompstrm_read_until_eof(struct decompstrm *strm, size_t *len_ret, char **buffer_ret)
{
    int error;
    bool eof = false;

    if (strm == NULL || (buffer_ret != NULL && len_ret == NULL))
        return DRPM_ERR_ARGS;

    while (!eof) {
        switch ((error = strm->read_chunk(strm))) {
        case DRPM_ERR_OK:
            break;
        case DRPM_ERR_FORMAT: // nothing more to read
            eof = true;
            break;
        default:
            return error;
        }
    }

    if (len_ret != NULL) {
        *len_ret = strm->data_len - strm->data_pos;
        if (buffer_ret != NULL) {
            if ((*buffer_ret = malloc(*len_ret)) == NULL)
                return DRPM_ERR_MEMORY;
            memcpy(*buffer_ret, strm->data + strm->data_pos, *len_ret);
            strm->data_pos = strm->data_len;
        }
    }

    return DRPM_ERR_OK;
}

int readchunk(struct decompstrm *strm)
{
    ssize_t in_len;
    char *data_tmp;
    char buffer[CHUNK_SIZE];

    if ((in_len = read(strm->filedesc, buffer, CHUNK_SIZE)) < 0)
        return DRPM_ERR_IO;

    if (in_len == 0)
        return DRPM_ERR_FORMAT;

    if ((data_tmp = realloc(strm->data, strm->data_len + in_len)) == NULL)
        return DRPM_ERR_MEMORY;

    strm->data = data_tmp;
    memcpy(strm->data + strm->data_len, buffer, in_len);
    strm->data_len += in_len;

    strm->read_len = strm->data_len;

    return DRPM_ERR_OK;
}

int readchunk_bzip2(struct decompstrm *strm)
{
    ssize_t in_len;
    char *data_tmp;
    char in_buffer[CHUNK_SIZE];
    char out_buffer[CHUNK_SIZE];
    size_t out_len;

    if ((in_len = read(strm->filedesc, in_buffer, CHUNK_SIZE)) < 0)
        return DRPM_ERR_IO;

    if (in_len == 0)
        return DRPM_ERR_FORMAT;

    strm->stream.bzip2.next_in = in_buffer;
    strm->stream.bzip2.avail_in = in_len;

    do {
        strm->stream.bzip2.next_out = out_buffer;
        strm->stream.bzip2.avail_out = CHUNK_SIZE;
        switch (BZ2_bzDecompress(&strm->stream.bzip2)) {
        case BZ_DATA_ERROR:
        case BZ_DATA_ERROR_MAGIC:
            return DRPM_ERR_FORMAT;
        case BZ_MEM_ERROR:
            return DRPM_ERR_MEMORY;
        }
        out_len = CHUNK_SIZE - strm->stream.bzip2.avail_out;
        if (out_len == 0)
            continue;
        if ((data_tmp = realloc(strm->data, strm->data_len + out_len))
            == NULL)
            return DRPM_ERR_MEMORY;
        strm->data = data_tmp;
        memcpy(strm->data + strm->data_len, out_buffer, out_len);
        strm->data_len += out_len;
    } while (!strm->stream.bzip2.avail_out);

    strm->read_len += in_len;

    return DRPM_ERR_OK;
}

int readchunk_gzip(struct decompstrm *strm)
{
    ssize_t in_len;
    char *data_tmp;
    unsigned char in_buffer[CHUNK_SIZE];
    unsigned char out_buffer[CHUNK_SIZE];
    size_t out_len;

    if ((in_len = read(strm->filedesc, in_buffer, CHUNK_SIZE)) < 0)
        return DRPM_ERR_IO;

    if (in_len == 0)
        return DRPM_ERR_FORMAT;

    strm->stream.gzip.next_in = in_buffer;
    strm->stream.gzip.avail_in = in_len;

    do {
        strm->stream.gzip.next_out = out_buffer;
        strm->stream.gzip.avail_out = CHUNK_SIZE;
        switch (inflate(&strm->stream.gzip, Z_SYNC_FLUSH)) {
        case Z_DATA_ERROR:
        case Z_NEED_DICT:
        case Z_STREAM_ERROR:
            return DRPM_ERR_FORMAT;
        case Z_MEM_ERROR:
            return DRPM_ERR_MEMORY;
        }
        out_len = CHUNK_SIZE - strm->stream.gzip.avail_out;
        if (out_len == 0)
            continue;
        if ((data_tmp = realloc(strm->data, strm->data_len + out_len))
            == NULL)
            return DRPM_ERR_MEMORY;
        strm->data = data_tmp;
        memcpy(strm->data + strm->data_len, out_buffer, out_len);
        strm->data_len += out_len;
    } while (!strm->stream.gzip.avail_out);

    strm->read_len += in_len;

    return DRPM_ERR_OK;
}

int readchunk_lzma(struct decompstrm *strm)
{
    ssize_t in_len;
    char *data_tmp;
    unsigned char in_buffer[CHUNK_SIZE];
    unsigned char out_buffer[CHUNK_SIZE];
    size_t out_len;

    if ((in_len = read(strm->filedesc, in_buffer, CHUNK_SIZE)) < 0)
        return DRPM_ERR_IO;

    if (in_len == 0)
        return DRPM_ERR_FORMAT;

    strm->stream.lzma.next_in = in_buffer;
    strm->stream.lzma.avail_in = in_len;

    do {
        strm->stream.lzma.next_out = out_buffer;
        strm->stream.lzma.avail_out = CHUNK_SIZE;
        switch (lzma_code(&strm->stream.lzma, LZMA_RUN)) {
        case LZMA_OK:
        case LZMA_STREAM_END:
            break;
        case LZMA_FORMAT_ERROR:
        case LZMA_OPTIONS_ERROR:
        case LZMA_DATA_ERROR:
        case LZMA_BUF_ERROR:
            return DRPM_ERR_FORMAT;
        case LZMA_MEM_ERROR:
            return DRPM_ERR_MEMORY;
        default:
            return DRPM_ERR_OTHER;
        }
        out_len = CHUNK_SIZE - strm->stream.lzma.avail_out;
        if (out_len == 0)
            continue;
        if ((data_tmp = realloc(strm->data, strm->data_len + out_len))
            == NULL)
            return DRPM_ERR_MEMORY;
        strm->data = data_tmp;
        memcpy(strm->data + strm->data_len, out_buffer, out_len);
        strm->data_len += out_len;
    } while (!strm->stream.lzma.avail_out);

    strm->read_len += in_len;

    return DRPM_ERR_OK;
}
