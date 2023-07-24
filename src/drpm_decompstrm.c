/*
    Authors:
        Pavel Tobias <ptobias@redhat.com>
        Matej Chalk <mchalk@redhat.com>

    Copyright (C) 2014 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 2.1 of the License, or
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
#ifdef HAVE_LZLIB_DEVEL
#include <lzlib.h>
#endif
#ifdef WITH_ZSTD
#include <zstd.h>
#endif
#include <openssl/evp.h>

/* magic bytes for determining compression type */
#define MAGIC_BZIP2(x) (((x) >> 40) == 0x425A68)
#define MAGIC_GZIP(x) (((x) >> 48) == 0x1F8B)
#define MAGIC_LZMA(x) (((x) >> 40) == 0x5D0000)
#define MAGIC_XZ(x) (((x) >> 16) == 0xFD377A585A00)
#define MAGIC_LZIP(x) (((x) >> 32) == 0x4C5A4950)
#define MAGIC_ZSTD(x) (((x) >> 32) == 0x28B52FFD)

struct decompstrm {
    unsigned char *data;
    size_t data_len;
    size_t data_pos;
    int filedesc;
    union {
        z_stream gzip;
        bz_stream bzip2;
        lzma_stream lzma;
#ifdef HAVE_LZLIB_DEVEL
        struct LZ_Decoder *lzip;
#endif
#ifdef WITH_ZSTD
        ZSTD_DCtx *zstd_context;
#endif
    } stream;
    bool lzip_eof;
    int (*read_chunk)(struct decompstrm *);
    void (*finish)(struct decompstrm *);
    size_t comp_size;
    EVP_MD_CTX *md5;
    const unsigned char *buffer;
    size_t buffer_len;
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

#ifdef HAVE_LZLIB_DEVEL
static void finish_lzip(struct decompstrm *);
static int init_lzip(struct decompstrm *);
static int readchunk_lzip(struct decompstrm *);

static int lzip_error(struct decompstrm *strm)
{
    switch (LZ_decompress_errno(strm->stream.lzip)) {
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
#endif

#ifdef WITH_ZSTD
static void finish_zstd(struct decompstrm *);
static int init_zstd(struct decompstrm *);
static int readchunk_zstd(struct decompstrm *);
#endif

/* Functions for finishing decompression for individual methods. */

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

#ifdef HAVE_LZLIB_DEVEL
void finish_lzip(struct decompstrm *strm)
{
    LZ_decompress_close(strm->stream.lzip);
}
#endif

#ifdef WITH_ZSTD
void finish_zstd(struct decompstrm *strm)
{
    ZSTD_freeDCtx(strm->stream.zstd_context);
}

#endif

/* Functions for initializing decompression for individual methods. */

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

#ifdef HAVE_LZLIB_DEVEL
int init_lzip(struct decompstrm *strm)
{
    int error;

    strm->read_chunk = readchunk_lzip;
    strm->finish = finish_lzip;
    strm->lzip_eof = false;

    if ((strm->stream.lzip = LZ_decompress_open()) == NULL)
        return DRPM_ERR_MEMORY;

    if ((error = lzip_error(strm)) != DRPM_ERR_OK)
        LZ_decompress_close(strm->stream.lzip);

    return error;
}
#endif

#ifdef WITH_ZSTD
int init_zstd(struct decompstrm *strm)
{
    if ((strm->stream.zstd_context = ZSTD_createDCtx()) == NULL)
        return DRPM_ERR_MEMORY;

    strm->read_chunk = readchunk_zstd;
    strm->finish = finish_zstd;

    return DRPM_ERR_OK;
}
#endif

/* Frees memory allocated by decompression stream. */
int decompstrm_destroy(struct decompstrm **strm)
{
    if (strm == NULL || *strm == NULL)
        return DRPM_ERR_PROG;

    if ((*strm)->finish != NULL)
        (*strm)->finish(*strm);

    free((*strm)->data);
    free(*strm);
    *strm = NULL;

    return DRPM_ERR_OK;
}

/* Initializes decompression stream.
 * The detected compression method will be stored in <*comp> (if not NULL).
 * If <md5> is not NULL, input data will be used to update the MD5 context.
 * If <filedesc> is valid, compressed data will be read from the file.
 * Otherwise, input data is read from <buffer> of size <buffer_len>. */
int decompstrm_init(struct decompstrm **strm, int filedesc, unsigned short *comp, EVP_MD_CTX *md5,
                    const unsigned char *buffer, size_t buffer_len)
{
    uint64_t magic;
    int error = DRPM_ERR_OK;

    if (strm == NULL || (filedesc < 0 && (buffer == NULL || buffer_len < 8)))
        return DRPM_ERR_PROG;

    if (filedesc < 0) {
        magic = parse_be64(buffer);
    } else {
        if ((error = read_be64(filedesc, &magic)) != DRPM_ERR_OK)
            return error;
        if (lseek(filedesc, -8, SEEK_CUR) == -1)
            return DRPM_ERR_IO;
    }

    if ((*strm = malloc(sizeof(struct decompstrm))) == NULL)
        return DRPM_ERR_MEMORY;

    (*strm)->data = NULL;
    (*strm)->data_len = 0;
    (*strm)->data_pos = 0;
    (*strm)->filedesc = filedesc;
    (*strm)->comp_size = 0;
    (*strm)->md5 = md5;
    (*strm)->buffer = buffer;
    (*strm)->buffer_len = buffer_len;

    if (MAGIC_GZIP(magic)) {
        if (comp != NULL)
            *comp = DRPM_COMP_GZIP;
        if ((error = init_gzip(*strm)) != DRPM_ERR_OK)
            goto cleanup_fail;
    } else if (MAGIC_BZIP2(magic)) {
        if (comp != NULL)
            *comp = DRPM_COMP_BZIP2;
        if ((error = init_bzip2(*strm)) != DRPM_ERR_OK)
            goto cleanup_fail;
    } else if (MAGIC_XZ(magic)) {
        if (comp != NULL)
            *comp = DRPM_COMP_XZ;
        if ((error = init_lzma(*strm)) != DRPM_ERR_OK)
            goto cleanup_fail;
    } else if (MAGIC_LZMA(magic)) {
        if (comp != NULL)
            *comp = DRPM_COMP_LZMA;
        if ((error = init_lzma(*strm)) != DRPM_ERR_OK)
            goto cleanup_fail;
#ifdef HAVE_LZLIB_DEVEL
    } else if (MAGIC_LZIP(magic)) {
        if (comp != NULL)
            *comp = DRPM_COMP_LZIP;
        if ((error = init_lzip(*strm)) != DRPM_ERR_OK)
            goto cleanup_fail;
#endif
#ifdef WITH_ZSTD
    } else if (MAGIC_ZSTD(magic)) {
        if (comp != NULL)
            *comp = DRPM_COMP_ZSTD;
        if ((error = init_zstd(*strm)) != DRPM_ERR_OK)
            goto cleanup_fail;
#endif
    } else {
        if (comp != NULL)
            *comp = DRPM_COMP_NONE;
        (*strm)->read_chunk = readchunk;
        (*strm)->finish = NULL;
    }

    return DRPM_ERR_OK;

cleanup_fail:
    free(*strm);
    *strm = NULL;

    return error;
}

/* Fetches size of *compressed* data. */
int decompstrm_get_comp_size(struct decompstrm *strm, size_t *size)
{
    if (strm == NULL || size == NULL)
        return DRPM_ERR_PROG;

    *size = strm->comp_size;

    return DRPM_ERR_OK;
}

int decompstrm_read_be32(struct decompstrm *strm, uint32_t *buffer_ret)
{
    int error;
    unsigned char bytes[4];

    if (strm == NULL)
        return DRPM_ERR_PROG;

    if ((error = decompstrm_read(strm, 4, bytes)) != DRPM_ERR_OK)
        return error;

    *buffer_ret = parse_be32(bytes);

    return DRPM_ERR_OK;
}

int decompstrm_read_be64(struct decompstrm *strm, uint64_t *buffer_ret)
{
    int error;
    unsigned char bytes[8];

    if (strm == NULL)
        return DRPM_ERR_PROG;

    if ((error = decompstrm_read(strm, 8, bytes)) != DRPM_ERR_OK)
        return error;

    *buffer_ret = parse_be64(bytes);

    return DRPM_ERR_OK;
}

/* Decompresses enough data to store <read_len> bytes at <buffer_ret>. */
int decompstrm_read(struct decompstrm *strm, size_t read_len, void *buffer_ret)
{
    int error;

    if (strm == NULL)
        return DRPM_ERR_PROG;

    if (UNSIGNED_SUM_OVERFLOWS(strm->data_len, read_len))
        return DRPM_ERR_OVERFLOW;

    while (strm->data_pos + read_len > strm->data_len)
        if ((error = strm->read_chunk(strm)) != DRPM_ERR_OK)
            return error;

    if (buffer_ret != NULL)
        memcpy(buffer_ret, strm->data + strm->data_pos, read_len);

    strm->data_pos += read_len;

    return DRPM_ERR_OK;
}

/* Decompresses the entire file and stores the result <*buffer_ret>
 * (and the size <*len_ret>). */
int decompstrm_read_until_eof(struct decompstrm *strm,
                              size_t *len_ret, unsigned char **buffer_ret)
{
    int error;
    bool eof = false;
    size_t data_len_prev;

    if (strm == NULL || (buffer_ret != NULL && len_ret == NULL))
        return DRPM_ERR_PROG;

    while (!eof) {
        data_len_prev = strm->data_len;
        switch ((error = strm->read_chunk(strm))) {
        case DRPM_ERR_OK:
            break;
        case DRPM_ERR_FORMAT: // nothing more to read
            eof = true;
            break;
        default:
            return error;
        }
        if (data_len_prev > strm->data_len)
            return DRPM_ERR_OVERFLOW;
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

/* Functions for decompressing chunks of data. */

// no compression
int readchunk(struct decompstrm *strm)
{
    ssize_t in_len;
    unsigned char *data_tmp;
    unsigned char buffer[CHUNK_SIZE];

    if (strm->filedesc < 0) {
        in_len = MIN(CHUNK_SIZE, strm->buffer_len);
        memcpy(buffer, strm->buffer, in_len);
        strm->buffer += in_len;
        strm->buffer_len -= in_len;
    } else {
        if ((in_len = read(strm->filedesc, buffer, CHUNK_SIZE)) < 0)
            return DRPM_ERR_IO;
    }

    if (in_len == 0)
        return DRPM_ERR_FORMAT;

    if ((data_tmp = realloc(strm->data, strm->data_len + in_len)) == NULL)
        return DRPM_ERR_MEMORY;

    strm->data = data_tmp;
    memcpy(strm->data + strm->data_len, buffer, in_len);
    strm->data_len += in_len;

    strm->comp_size = strm->data_len;

    if (strm->md5 != NULL && EVP_DigestUpdate(strm->md5, buffer, in_len) != 1)
        return DRPM_ERR_OTHER;

    return DRPM_ERR_OK;
}

int readchunk_bzip2(struct decompstrm *strm)
{
    ssize_t in_len;
    unsigned char *data_tmp;
    char in_buffer[CHUNK_SIZE];
    char out_buffer[CHUNK_SIZE];
    size_t out_len;

    if (strm->filedesc < 0) {
        in_len = MIN(CHUNK_SIZE, strm->buffer_len);
        memcpy(in_buffer, strm->buffer, in_len);
        strm->buffer += in_len;
        strm->buffer_len -= in_len;
    } else {
        if ((in_len = read(strm->filedesc, in_buffer, CHUNK_SIZE)) < 0)
            return DRPM_ERR_IO;
    }

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

    strm->comp_size += in_len;

    if (strm->md5 != NULL && EVP_DigestUpdate(strm->md5, in_buffer, in_len) != 1)
        return DRPM_ERR_OTHER;

    return DRPM_ERR_OK;
}

int readchunk_gzip(struct decompstrm *strm)
{
    ssize_t in_len;
    unsigned char *data_tmp;
    unsigned char in_buffer[CHUNK_SIZE];
    unsigned char out_buffer[CHUNK_SIZE];
    size_t out_len;

    if (strm->filedesc < 0) {
        in_len = MIN(CHUNK_SIZE, strm->buffer_len);
        memcpy(in_buffer, strm->buffer, in_len);
        strm->buffer += in_len;
        strm->buffer_len -= in_len;
    } else {
        if ((in_len = read(strm->filedesc, in_buffer, CHUNK_SIZE)) < 0)
            return DRPM_ERR_IO;
    }

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

    strm->comp_size += in_len;

    if (strm->md5 != NULL && EVP_DigestUpdate(strm->md5, in_buffer, in_len) != 1)
        return DRPM_ERR_OTHER;

    return DRPM_ERR_OK;
}

int readchunk_lzma(struct decompstrm *strm)
{
    ssize_t in_len;
    unsigned char *data_tmp;
    unsigned char in_buffer[CHUNK_SIZE];
    unsigned char out_buffer[CHUNK_SIZE];
    size_t out_len;

    if (strm->filedesc < 0) {
        in_len = MIN(CHUNK_SIZE, strm->buffer_len);
        memcpy(in_buffer, strm->buffer, in_len);
        strm->buffer += in_len;
        strm->buffer_len -= in_len;
    } else {
        if ((in_len = read(strm->filedesc, in_buffer, CHUNK_SIZE)) < 0)
            return DRPM_ERR_IO;
    }

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

    strm->comp_size += in_len;

    if (strm->md5 != NULL && EVP_DigestUpdate(strm->md5, in_buffer, in_len) != 1)
        return DRPM_ERR_OTHER;

    return DRPM_ERR_OK;
}

#ifdef HAVE_LZLIB_DEVEL
int readchunk_lzip(struct decompstrm *strm)
{
    int error;
    unsigned char *data_tmp;
    ssize_t in_len;
    unsigned char in_buffer[CHUNK_SIZE];
    unsigned char out_buffer[CHUNK_SIZE];
    size_t out_len;
    ssize_t written = 0;
    int wr;
    int rd;

    if (strm->lzip_eof)
        return DRPM_ERR_FORMAT;

    if (strm->filedesc < 0) {
        in_len = MIN(CHUNK_SIZE, strm->buffer_len);
        memcpy(in_buffer, strm->buffer, in_len);
        strm->buffer += in_len;
        strm->buffer_len -= in_len;
    } else {
        if ((in_len = read(strm->filedesc, in_buffer, CHUNK_SIZE)) < 0)
            return DRPM_ERR_IO;
    }

    if (in_len == 0) {
        strm->lzip_eof = true;
        LZ_decompress_finish(strm->stream.lzip);
        do {
            if ((rd = LZ_decompress_read(strm->stream.lzip, out_buffer, CHUNK_SIZE)) < 0) {
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
        } while (!LZ_decompress_finished(strm->stream.lzip));
    } else {
        while (written < in_len) {
            if (LZ_decompress_write_size(strm->stream.lzip) > 0) {
                if ((wr = LZ_decompress_write(strm->stream.lzip,
                                              in_buffer + written,
                                              in_len - written)) < 0) {
                    error = lzip_error(strm);
                    return error == DRPM_ERR_OK ? DRPM_ERR_OTHER : error;
                }
                written += wr;
            }
            if ((rd = LZ_decompress_read(strm->stream.lzip, out_buffer, CHUNK_SIZE)) < 0) {
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
    }

    strm->comp_size += in_len;

    if (strm->md5 != NULL && EVP_DigestUpdate(strm->md5, in_buffer, in_len) != 1)
        return DRPM_ERR_OTHER;

    return DRPM_ERR_OK;
}
#endif

#ifdef WITH_ZSTD
int readchunk_zstd(struct decompstrm *strm)
{
    ssize_t in_len;
    unsigned char *data_tmp;
    unsigned char in_buffer[CHUNK_SIZE];

    if (strm->filedesc < 0) {
        in_len = MIN(CHUNK_SIZE, strm->buffer_len);
        memcpy(in_buffer, strm->buffer, in_len);
        strm->buffer += in_len;
        strm->buffer_len -= in_len;
    } else {
        if ((in_len = read(strm->filedesc, in_buffer, CHUNK_SIZE)) < 0)
            return DRPM_ERR_IO;
    }

    if (in_len == 0)
        return DRPM_ERR_FORMAT;

    size_t const buffOutSize = ZSTD_DStreamOutSize();
    void* const buffOut = malloc(buffOutSize);
    if (buffOut == NULL)
        return DRPM_ERR_MEMORY;

    ZSTD_inBuffer input = { in_buffer, in_len, 0 };

    while (input.pos < input.size) {
        ZSTD_outBuffer output = { buffOut, buffOutSize, 0 };
        size_t const ret = ZSTD_decompressStream(strm->stream.zstd_context, &output , &input);
        if (ZSTD_isError(ret))
            return DRPM_ERR_OTHER;
        if (output.pos == 0)
            continue;
        if ((data_tmp = realloc(strm->data, strm->data_len + output.pos)) == NULL)
            return DRPM_ERR_MEMORY;
        strm->data = data_tmp;
        memcpy(strm->data + strm->data_len, buffOut, output.pos);
        strm->data_len += output.pos;
    }

    strm->comp_size += in_len;

    if (strm->md5 != NULL && EVP_DigestUpdate(strm->md5, in_buffer, in_len) != 1)
        return DRPM_ERR_OTHER;

    free(buffOut);
    return DRPM_ERR_OK;
}
#endif
