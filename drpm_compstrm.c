#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <zlib.h>
#include <bzlib.h>
#include <lzma.h>

#include "drpm.h"
#include "drpm_private.h"

#define CHUNK_SIZE 1024
#define MAGIC_BZIP2(x) (((x) >> 16) == 0x425A)
#define MAGIC_GZIP(x) (((x) >> 16) == 0x1F8B)
#define MAGIC_LZMA(x) (((x) >> 8) == 0x5D0000)
#define MAGIC_XZ(x) ((x) == 0xFD377A58)

struct compstrm {
    char *data;
    size_t data_len;
    size_t data_pos;
    int filedesc;
    union {
        z_stream gzip;
        bz_stream bzip2;
        lzma_stream lzma;
    } stream;
    int (*read_chunk)(struct compstrm *);
    void (*finish)(struct compstrm *);
};

static void finish_bzip2(struct compstrm *);
static void finish_gzip(struct compstrm *);
static void finish_lzma(struct compstrm *);
static int init_bzip2(struct compstrm *);
static int init_gzip(struct compstrm *);
static int init_lzma(struct compstrm *);
static int readchunk(struct compstrm *);
static int readchunk_bzip2(struct compstrm *);
static int readchunk_gzip(struct compstrm *);
static int readchunk_lzma(struct compstrm *);

void finish_bzip2(struct compstrm *strm)
{
    BZ2_bzDecompressEnd(&strm->stream.bzip2);
}

void finish_gzip(struct compstrm *strm)
{
    inflateEnd(&strm->stream.gzip);
}

void finish_lzma(struct compstrm *strm)
{
    lzma_end(&strm->stream.lzma);
}

int init_bzip2(struct compstrm *strm)
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

int init_gzip(struct compstrm *strm)
{
    strm->read_chunk = readchunk_gzip;
    strm->finish = finish_gzip;
    strm->stream.gzip.zalloc = NULL;
    strm->stream.gzip.zfree = NULL;
    strm->stream.gzip.opaque = NULL;
    strm->stream.gzip.next_in = NULL;
    strm->stream.gzip.avail_in = 0;

    switch (inflateInit2(&strm->stream.gzip, 16 + MAX_WBITS)) {
    case Z_VERSION_ERROR:
        return DRPM_ERR_CONFIG;
    case Z_MEM_ERROR:
        return DRPM_ERR_MEMORY;
    }

    return DRPM_ERR_OK;
}

int init_lzma(struct compstrm *strm)
{
    lzma_stream stream = LZMA_STREAM_INIT;

    strm->read_chunk = readchunk_lzma;
    strm->finish = finish_lzma;
    strm->stream.lzma = stream;

    switch (lzma_auto_decoder(&strm->stream.lzma, UINT64_MAX,
                                LZMA_CONCATENATED)) {
    case LZMA_OK:
        break;
    case LZMA_MEM_ERROR:
        lzma_end(&strm->stream.lzma);
        return DRPM_ERR_MEMORY;
    default:
        lzma_end(&strm->stream.lzma);
        return DRPM_ERR_FORMAT;
    }

    return DRPM_ERR_OK;
}

int compstrm_destroy(struct compstrm **strm)
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

int compstrm_init(struct compstrm **strm, int filedesc, uint32_t *comp)
{
    uint32_t magic;
    int error;

    if (strm == NULL)
        return DRPM_ERR_ARGS;

    if ((error = read_be32(filedesc, &magic)) != DRPM_ERR_OK)
        return error;

    if (lseek(filedesc, -4, SEEK_CUR) == -1)
        return DRPM_ERR_IO;

    if ((*strm = malloc(sizeof(struct compstrm))) == NULL)
        return DRPM_ERR_MEMORY;

    (*strm)->data = NULL;
    (*strm)->data_len = 0;
    (*strm)->data_pos = 0;
    (*strm)->filedesc = filedesc;

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

int compstrm_read_be32(struct compstrm *strm, uint32_t *buffer_ret)
{
    int error;
    char bytes[4];

    if (strm == NULL)
        return DRPM_ERR_ARGS;

    if ((error = compstrm_read(strm, 4, bytes)) != DRPM_ERR_OK)
        return error;

    *buffer_ret = parse_be32(bytes);

    return DRPM_ERR_OK;
}

int compstrm_read(struct compstrm *strm, size_t read_len, char *buffer_ret)
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

int readchunk(struct compstrm *strm)
{
    ssize_t in_len;
    char *data_tmp;
    char buffer[CHUNK_SIZE];

    if ((in_len = read(strm->filedesc, buffer, CHUNK_SIZE)) <= 0)
        return DRPM_ERR_IO;

    if ((data_tmp = realloc(strm->data, strm->data_len + in_len)) == NULL)
        return DRPM_ERR_MEMORY;

    strm->data = data_tmp;
    memcpy(strm->data + strm->data_len, buffer, in_len);
    strm->data_len += in_len;

    return DRPM_ERR_OK;
}

int readchunk_bzip2(struct compstrm *strm)
{
    ssize_t in_len;
    char *data_tmp;
    char in_buffer[CHUNK_SIZE];
    char out_buffer[CHUNK_SIZE];
    size_t out_len;

    if ((in_len = read(strm->filedesc, in_buffer, CHUNK_SIZE)) <= 0)
        return DRPM_ERR_IO;

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

    return DRPM_ERR_OK;
}

int readchunk_gzip(struct compstrm *strm)
{
    ssize_t in_len;
    char *data_tmp;
    unsigned char in_buffer[CHUNK_SIZE];
    unsigned char out_buffer[CHUNK_SIZE];
    size_t out_len;

    if ((in_len = read(strm->filedesc, in_buffer, CHUNK_SIZE)) <= 0)
        return DRPM_ERR_IO;

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

    return DRPM_ERR_OK;
}

int readchunk_lzma(struct compstrm *strm)
{
    ssize_t in_len;
    char *data_tmp;
    unsigned char in_buffer[CHUNK_SIZE];
    unsigned char out_buffer[CHUNK_SIZE];
    size_t out_len;

    if ((in_len = read(strm->filedesc, in_buffer, CHUNK_SIZE)) <= 0)
        return DRPM_ERR_IO;

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

    return DRPM_ERR_OK;
}
