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

#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <rpm/rpmlib.h>
#include <openssl/md5.h>

#define BUFFER_SIZE 4096

#define PADDING_BYTES(offset) ((8 - ((offset) % 8)) % 8)

struct rpm {
    unsigned char lead[96];
    Header signature;
    Header header;
    unsigned char *archive;
    uint64_t archive_size;
    uint64_t archive_offset;
};

static void rpm_init(struct rpm *);
static void rpm_free(struct rpm *);
static int rpm_read_archive(struct rpm *, const char *, off_t);

void rpm_init(struct rpm *rpmst)
{
    for (int i = 0; i < 96; i++)
        rpmst->lead[i] = 0;

    rpmst->signature = NULL;
    rpmst->header = NULL;
    rpmst->archive = NULL;
    rpmst->archive_size = 0;
    rpmst->archive_offset = 0;
}

void rpm_free(struct rpm *rpmst)
{
    headerFree(rpmst->signature);
    headerFree(rpmst->header);
    free(rpmst->archive);

    rpm_init(rpmst);
}

int rpm_read_archive(struct rpm *rpmst, const char *filename, off_t offset)
{
    int filedesc;
    unsigned char *archive_tmp;
    unsigned char buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    int error = DRPM_ERR_OK;

    if (rpmst == NULL || filename == NULL || offset < 0)
        return DRPM_ERR_ARGS;

    if ((filedesc = open(filename, O_RDONLY)) < 0)
        return DRPM_ERR_IO;

    if (lseek(filedesc, offset, SEEK_SET) != offset) {
        error = DRPM_ERR_IO;
        goto cleanup;
    }

    while ((bytes_read = read(filedesc, buffer, BUFFER_SIZE)) > 0) {
        if ((archive_tmp = realloc(rpmst->archive,
             rpmst->archive_size + bytes_read)) == NULL) {
            error = DRPM_ERR_MEMORY;
            free(rpmst->archive);
            goto cleanup;
        }
        rpmst->archive = archive_tmp;
        memcpy(rpmst->archive + rpmst->archive_size, buffer, bytes_read);
        rpmst->archive_size += bytes_read;
    }

    if (bytes_read < 0)
        error = DRPM_ERR_IO;

cleanup:
    close(filedesc);

    return error;
}

int rpm_read(struct rpm **rpmst, const char *filename, bool include_archive)
{
    FD_t file;
    unsigned char magic_rpm[4] = {0xED, 0xAB, 0xEE, 0xDB};
    off_t file_pos;
    int error = DRPM_ERR_OK;

    if (rpmst == NULL || filename == NULL)
        return DRPM_ERR_ARGS;

    if ((*rpmst = malloc(sizeof(struct rpm))) == NULL)
        return DRPM_ERR_MEMORY;

    rpm_init(*rpmst);

    if ((file = Fopen(filename, "rb")) == NULL)
        return DRPM_ERR_IO;

    if (Fread((*rpmst)->lead, 1, 96, file) != 96 ||
        memcmp((*rpmst)->lead, magic_rpm, 4) != 0 ||
        ((*rpmst)->signature = headerRead(file, HEADER_MAGIC_YES)) == NULL ||
        (file_pos = Ftell(file)) < 0 ||
        Fseek(file, PADDING_BYTES(file_pos), SEEK_CUR) < 0 ||
        ((*rpmst)->header = headerRead(file, HEADER_MAGIC_YES)) == NULL) {
        error = Ferror(file) ? DRPM_ERR_IO : DRPM_ERR_FORMAT;
        goto cleanup_fail;
    }

    if (include_archive) {
        if ((error = rpm_read_archive(*rpmst, filename, Ftell(file))) != DRPM_ERR_OK)
            goto cleanup_fail;
    }

    goto cleanup;

cleanup_fail:
    rpm_free(*rpmst);

cleanup:
    Fclose(file);

    return error;
}

int rpm_destroy(struct rpm **rpmst)
{
    if (rpmst == NULL)
        return DRPM_ERR_ARGS;

    rpm_free(*rpmst);
    free(*rpmst);
    *rpmst = NULL;

    return DRPM_ERR_OK;
}

ssize_t rpm_archive_read_chunk(struct rpm *rpmst, unsigned char *buffer, size_t count)
{
    if (rpmst == NULL || buffer == NULL)
        return -1;

    if (rpmst->archive_offset >= rpmst->archive_size)
        return 0;

    if (rpmst->archive_offset + count > rpmst->archive_size)
        count = rpmst->archive_size - rpmst->archive_offset;

    memcpy(buffer, rpmst->archive + rpmst->archive_offset, count);
    rpmst->archive_offset += count;

    return count;
}

uint32_t rpm_size_full(struct rpm *rpmst)
{
    if (rpmst == NULL)
        return 0;

    unsigned sig_size = headerSizeof(rpmst->signature, HEADER_MAGIC_YES);

    return 96 + sig_size + PADDING_BYTES(sig_size) +
           headerSizeof(rpmst->header, HEADER_MAGIC_YES) +
           rpmst->archive_size;
}

uint32_t rpm_size_header(struct rpm *rpmst)
{
    if (rpmst == NULL)
        return 0;

    return headerSizeof(rpmst->header, HEADER_MAGIC_YES);
}

int rpm_fetch_lead_and_signature(struct rpm *rpmst, unsigned char **lead_sig, uint32_t *len)
{
    void *signature;
    unsigned signature_size;
    int error = DRPM_ERR_OK;

    if (rpmst == NULL || lead_sig == NULL || len == NULL)
        return DRPM_ERR_ARGS;

    *lead_sig = NULL;
    *len = 0;

    if ((signature = headerExport(rpmst->signature, &signature_size)) == NULL ||
        (*lead_sig = malloc(96 + signature_size)) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup;
    }

    memcpy(*lead_sig, rpmst->lead, 96);
    memcpy(*lead_sig + 96, signature, signature_size);
    *len = 96 + signature_size;

cleanup:
    free(signature);

    return error;
}

int rpm_fetch_header(struct rpm *rpmst, unsigned char **header_ret, uint32_t *len)
{
    void *header;
    unsigned header_size;
    int error = DRPM_ERR_OK;

    if (rpmst == NULL || header_ret == NULL || len == NULL)
        return DRPM_ERR_ARGS;

    *header_ret = NULL;
    *len = 0;

    if ((header = headerExport(rpmst->header, &header_size)) == NULL ||
        (*header_ret = malloc(header_size)) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup;
    }

    memcpy(*header_ret, header, header_size);
    *len = header_size;

cleanup:
    free(header);

    return error;
}

int rpm_write(struct rpm *rpmst, const char *filename, bool include_archive)
{
    FD_t file;
    ssize_t padding_bytes;
    unsigned char padding[7] = {0};
    int error = DRPM_ERR_OK;

    if (rpmst == NULL)
        return DRPM_ERR_ARGS;

    if ((file = Fopen(filename, "wb")) == NULL)
        return DRPM_ERR_IO;

    if (Fwrite(rpmst->lead, 1, 96, file) != 96) {
        error = DRPM_ERR_IO;
        goto cleanup;
    }

    if (headerWrite(file, rpmst->signature, HEADER_MAGIC_YES) != 0) {
        error = DRPM_ERR_IO;
        goto cleanup;
    }

    if ((padding_bytes = PADDING_BYTES(Ftell(file))) > 0) {
        if (Fwrite(padding, 1, padding_bytes, file) != padding_bytes) {
            error = DRPM_ERR_IO;
            goto cleanup;
        }
    }

    if (headerWrite(file, rpmst->header, HEADER_MAGIC_YES) != 0) {
        error = DRPM_ERR_IO;
        goto cleanup;
    }

    if (include_archive) {
        if (Fwrite(rpmst->archive, 1, rpmst->archive_size, file)
            != (ssize_t)rpmst->archive_size) {
            error = DRPM_ERR_IO;
            goto cleanup;
        }
    }

cleanup:
    Fclose(file);
    return error;
}

int rpm_add_lead_to_md5(struct rpm *rpmst, MD5_CTX *md5)
{
    if (rpmst == NULL || md5 == NULL)
        return DRPM_ERR_ARGS;

    if (MD5_Update(md5, rpmst->lead, 96) != 1)
        return DRPM_ERR_CONFIG;

    return DRPM_ERR_OK;
}

int rpm_add_signature_to_md5(struct rpm *rpmst, MD5_CTX *md5)
{
    void *signature;
    unsigned signature_size;

    if (rpmst == NULL || md5 == NULL)
        return DRPM_ERR_ARGS;

    if ((signature = headerExport(rpmst->signature, &signature_size)) == NULL)
        return DRPM_ERR_MEMORY;

    if (MD5_Update(md5, signature, signature_size) != 1) {
        free(signature);
        return DRPM_ERR_CONFIG;
    }

    free(signature);

    return DRPM_ERR_OK;
}

int rpm_add_header_to_md5(struct rpm *rpmst, MD5_CTX *md5)
{
    void *header;
    unsigned int header_size;

    if (rpmst == NULL || md5 == NULL)
        return DRPM_ERR_ARGS;

    if ((header = headerExport(rpmst->header, &header_size)) == NULL)
        return DRPM_ERR_MEMORY;

    if (MD5_Update(md5, header, header_size) != 1) {
        free(header);
        return DRPM_ERR_CONFIG;
    }

    free(header);

    return DRPM_ERR_OK;
}

int rpm_add_archive_to_md5(struct rpm *rpmst, MD5_CTX *md5)
{
    if (rpmst == NULL || md5 == NULL)
        return DRPM_ERR_ARGS;

    if (MD5_Update(md5, rpmst->archive, rpmst->archive_size) != 1)
        return DRPM_ERR_CONFIG;

    return DRPM_ERR_OK;
}

int rpm_get_nevr(struct rpm *rpmst, char **nevr)
{
    if (rpmst == NULL || nevr == NULL)
        return DRPM_ERR_ARGS;

    if ((*nevr = headerGetAsString(rpmst->header, RPMTAG_NEVR)) == NULL)
        return DRPM_ERR_MEMORY;

    return DRPM_ERR_OK;
}

int rpm_get_comp(struct rpm *rpmst, uint32_t *comp)
{
    const char *payload_comp;

    if (rpmst == NULL || comp == NULL)
        return DRPM_ERR_ARGS;

    if ((payload_comp = headerGetString(rpmst->header, RPMTAG_PAYLOADCOMPRESSOR)) == NULL)
        return DRPM_ERR_FORMAT;

    if (strcmp(payload_comp, "gzip") == 0) {
        *comp = DRPM_COMP_GZIP;
    } else if (strcmp(payload_comp, "bzip2") == 0) {
        *comp = DRPM_COMP_BZIP2;
    } else if (strcmp(payload_comp, "lzip") == 0) {
        *comp = DRPM_COMP_LZIP;
    } else if (strcmp(payload_comp, "lzma") == 0) {
        *comp = DRPM_COMP_LZMA;
    } else if (strcmp(payload_comp, "xz") == 0) {
        *comp = DRPM_COMP_XZ;
    } else {
        return DRPM_ERR_FORMAT;
    }

    return DRPM_ERR_OK;
}

int rpm_get_payload_format(struct rpm *rpmst, unsigned short *payfmt)
{
    const char *payload_format;

    if (rpmst == NULL || payfmt == NULL)
        return DRPM_ERR_ARGS;

    if ((payload_format = headerGetString(rpmst->header, RPMTAG_PAYLOADFORMAT)) == NULL)
        return DRPM_ERR_MEMORY;

    if (strcmp(payload_format, "cpio") == 0) {
        *payfmt = PAYLOAD_FORMAT_CPIO;
    } else if (strcmp(payload_format, "xar") == 0) {
        *payfmt = PAYLOAD_FORMAT_XAR;
    } else {
        return DRPM_ERR_FORMAT;
    }

    return DRPM_ERR_OK;
}

int rpm_patch_payload_format(struct rpm *rpmst, const char *new_payfmt)
{
    if (rpmst == NULL || new_payfmt == NULL)
        return DRPM_ERR_ARGS;

    if (headerPutString(rpmst->header, RPMTAG_PAYLOADFORMAT, new_payfmt) != 1)
        return DRPM_ERR_FORMAT;

    return DRPM_ERR_OK;
}

int rpm_get_payload_format_offset(struct rpm *rpmst, uint32_t *offset)
{
    char *header;
    unsigned header_size;
    uint32_t index_count;
    int error = DRPM_ERR_FORMAT;

    if (rpmst == NULL || offset == NULL)
        return DRPM_ERR_ARGS;

    if ((header = headerExport(rpmst->header, &header_size)) == NULL)
        return DRPM_ERR_MEMORY;

    index_count = parse_be32(header + 8);

    for (uint32_t i = 0, off = 16; i < index_count && off+16 <= header_size;
         i++, off += i*16) {
        if (parse_be32(header + off) == RPMTAG_PAYLOADFORMAT) {
            *offset = parse_be32(header + off + 8);
            error = DRPM_ERR_OK;
            goto cleanup;
        }
    }

cleanup:
    free(header);

    return error;
}

int rpm_get_comp_only(const char *filename, unsigned short *ret)
{
    struct rpm *rpmst = NULL;
    uint32_t comp;
    int error = DRPM_ERR_OK;

    if (filename == NULL || ret == NULL)
        return DRPM_ERR_ARGS;

    if ((error = rpm_read(&rpmst, filename, false)) != DRPM_ERR_OK ||
        (error = rpm_get_comp(rpmst, &comp)) != DRPM_ERR_OK)
        goto cleanup;

    *ret = comp;

cleanup:
    if (error == DRPM_ERR_OK)
        error = rpm_destroy(&rpmst);
    else
        rpm_destroy(&rpmst);

    return error;
}

int rpm_signature_empty(struct rpm *rpmst)
{
    if (rpmst == NULL)
        return DRPM_ERR_ARGS;

    headerFree(rpmst->signature);
    rpmst->signature = headerNew();

    return DRPM_ERR_OK;
}

int rpm_signature_set_size(struct rpm *rpmst, uint32_t size)
{
    rpmtd tag_data = rpmtdNew();
    uint32_t size_var = size;

    if (rpmst == NULL)
        return DRPM_ERR_ARGS;

    tag_data->tag = RPMSIGTAG_SIZE;
    tag_data->type = RPM_INT32_TYPE;
    tag_data->data = &size_var;
    tag_data->count = 1;

    headerPut(rpmst->signature, tag_data, HEADERPUT_DEFAULT);

    rpmtdFree(tag_data);

    return DRPM_ERR_OK;
}

int rpm_signature_set_md5(struct rpm *rpmst, unsigned char md5[16])
{
    rpmtd tag_data = rpmtdNew();

    if (rpmst == NULL)
        return DRPM_ERR_ARGS;

    tag_data->tag = RPMSIGTAG_MD5;
    tag_data->type = RPM_BIN_TYPE;
    tag_data->data = md5;
    tag_data->count = 16;

    headerPut(rpmst->signature, tag_data, HEADERPUT_DEFAULT);

    rpmtdFree(tag_data);

    return DRPM_ERR_OK;
}

int rpm_signature_set_headersignatures(struct rpm *rpmst, unsigned char hdrsig[16])
{
    rpmtd tag_data = rpmtdNew();

    if (rpmst == NULL)
        return DRPM_ERR_ARGS;

    tag_data->tag = RPMTAG_HEADERSIGNATURES;
    tag_data->type = RPM_BIN_TYPE;
    tag_data->data = hdrsig;
    tag_data->count = 16;

    headerPut(rpmst->signature, tag_data, HEADERPUT_DEFAULT);

    rpmtdFree(tag_data);

    return DRPM_ERR_OK;
}

int rpm_rewrite_signature(struct rpm *rpmst, int filedesc)
{
    int error = DRPM_ERR_OK;
    void *signature = NULL;
    unsigned signature_size = 0;
    off_t offset;

    if ((offset = lseek(filedesc, 0, SEEK_CUR)) == (off_t)-1 ||
        lseek(filedesc, 96, SEEK_SET) == (off_t)-1)
        return DRPM_ERR_IO;

    if ((signature = headerExport(rpmst->signature, &signature_size)) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup;
    }

    if (write(filedesc, signature, signature_size) != signature_size) {
        error = DRPM_ERR_IO;
        goto cleanup;
    }

cleanup:
    if (lseek(filedesc, offset, SEEK_SET) == (off_t)-1)
        error = DRPM_ERR_IO;

    free(signature);

    return error;
}
