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
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/md5.h>

#define MAGIC_DRPM 0x6472706D
#define MAGIC_RPM 0xEDABEEDB

#define MAGIC_DLT(x) (((x) >> 8) == 0x444C54)
#define MAGIC_DLT3(x) ((x) == 0x444C5433)

#define RPM_LEADSIG_MIN_LEN 112 /* 96B rpmlead + 16B signature intro */

static int readdelta_rest(int, struct deltarpm *);
static int readdelta_rpmonly(int, struct deltarpm *);
static int readdelta_standard(int, struct deltarpm *);

int read_be32(int filedesc, uint32_t *buffer_ret)
{
    unsigned char buffer[4];

    switch (read(filedesc, buffer, 4)) {
    case 4:
        break;
    case -1:
        return DRPM_ERR_IO;
    default:
        return DRPM_ERR_FORMAT;
    }

    *buffer_ret = parse_be32(buffer);

    return DRPM_ERR_OK;
}

int read_be64(int filedesc, uint64_t *buffer_ret)
{
    unsigned char buffer[8];

    switch (read(filedesc, buffer, 8)) {
    case 8:
        break;
    case -1:
        return DRPM_ERR_IO;
    default:
        return DRPM_ERR_FORMAT;
    }

    *buffer_ret = parse_be64(buffer);

    return DRPM_ERR_OK;
}

int readdelta_rest(int filedesc, struct deltarpm *delta)
{
    struct decompstrm *stream;
    uint32_t version;
    uint32_t src_nevr_len;
    uint32_t deltarpm_comp;
    uint32_t offadj_elems_size;
    uint32_t int_copies_size;
    uint32_t ext_copies_size;
    uint32_t ext_data_32;
    uint32_t int_data_32;
    uint64_t off;
    int error = DRPM_ERR_OK;

    if ((error = decompstrm_init(&stream, filedesc, &delta->comp, NULL)) != DRPM_ERR_OK)
        return error;

    if ((error = decompstrm_read_be32(stream, &version)) != DRPM_ERR_OK)
        goto cleanup;

    if (!MAGIC_DLT(version)) {
        error = DRPM_ERR_FORMAT;
        goto cleanup;
    }

    delta->version = version % 256 - '0';

    printf("delta version: %u\n", delta->version);

    if (delta->version < 3 && delta->type == DRPM_TYPE_RPMONLY) {
        error = DRPM_ERR_FORMAT;
        goto cleanup;
    }

    if ((error = decompstrm_read_be32(stream, &src_nevr_len)) != DRPM_ERR_OK)
        goto cleanup;

    if ((delta->src_nevr = malloc(src_nevr_len + 1)) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup;
    }

    if ((error = decompstrm_read(stream, src_nevr_len, delta->src_nevr)) != DRPM_ERR_OK)
        goto cleanup;

    delta->src_nevr[src_nevr_len] = '\0';

    printf("source NEVR: %s\n", delta->src_nevr);

    if ((error = decompstrm_read_be32(stream, &delta->sequence_len)) != DRPM_ERR_OK)
        goto cleanup;

    if (delta->sequence_len < MD5_DIGEST_LENGTH ||
        (delta->sequence_len != MD5_DIGEST_LENGTH && delta->type == DRPM_TYPE_RPMONLY)) {
        error = DRPM_ERR_FORMAT;
        goto cleanup;
    }

    if ((delta->sequence = malloc(delta->sequence_len)) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup;
    }

    if ((error = decompstrm_read(stream, delta->sequence_len, delta->sequence)) != DRPM_ERR_OK)
        goto cleanup;

    char *sequence = malloc(delta->sequence_len * 2 + 1);
    dump_hex(sequence, delta->sequence, delta->sequence_len);
    printf("sequence: %.32s %s\n", sequence, sequence + MD5_DIGEST_LENGTH * 2);
    free(sequence);

    if ((error = decompstrm_read(stream, MD5_DIGEST_LENGTH, delta->tgt_md5)) != DRPM_ERR_OK)
        goto cleanup;

    char md5[MD5_DIGEST_LENGTH * 2 + 1];
    dump_hex(md5, delta->tgt_md5, MD5_DIGEST_LENGTH);
    printf("target MD5: %s\n", md5);

    if (delta->version >= 2) {
        if ((error = decompstrm_read_be32(stream, &delta->tgt_size)) != DRPM_ERR_OK ||
            (error = decompstrm_read_be32(stream, &deltarpm_comp)) != DRPM_ERR_OK)
            goto cleanup;

        printf("target size: %u\n", delta->tgt_size);

        if (!deltarpm_decode_comp(deltarpm_comp, &delta->tgt_comp, &delta->tgt_comp_level)) {
            error = DRPM_ERR_FORMAT;
            goto cleanup;
        }

        printf("target compression: %s (%u)\n", comp2str(delta->tgt_comp), delta->tgt_comp_level);

        if ((error = decompstrm_read_be32(stream, &delta->tgt_comp_param_len)) != DRPM_ERR_OK)
            goto cleanup;

        if (delta->tgt_comp_param_len > 0) {
            if ((delta->tgt_comp_param = malloc(delta->tgt_comp_param_len)) == NULL) {
                error = DRPM_ERR_MEMORY;
                goto cleanup;
            }

            if ((error = decompstrm_read(stream, delta->tgt_comp_param_len, delta->tgt_comp_param)) != DRPM_ERR_OK)
                goto cleanup;
        }

        char *comp_param = malloc(delta->tgt_comp_param_len * 2 + 1);
        dump_hex(comp_param, delta->tgt_comp_param, delta->tgt_comp_param_len);
        printf("target compression parameter block: %s\n", comp_param);
        free(comp_param);

        if (delta->version == 3) {
            if ((error = decompstrm_read_be32(stream, &delta->tgt_header_len)) != DRPM_ERR_OK ||
                (error = decompstrm_read_be32(stream, &delta->offadj_elems_count)) != DRPM_ERR_OK)
                goto cleanup;

            printf("target header length: %u\n", delta->tgt_header_len);

            if (delta->offadj_elems_count > 0) {
                offadj_elems_size = delta->offadj_elems_count * 2;
                if ((delta->offadj_elems = malloc(offadj_elems_size * 4)) == NULL) {
                    error = DRPM_ERR_MEMORY;
                    goto cleanup;
                }
                for (uint32_t i = 0; i < offadj_elems_size; i += 2)
                    if ((error = decompstrm_read_be32(stream, delta->offadj_elems + i)) != DRPM_ERR_OK)
                        goto cleanup;
                for (uint32_t j = 1; j < offadj_elems_size; j += 2) {
                    if ((error = decompstrm_read_be32(stream, delta->offadj_elems + j)) != DRPM_ERR_OK)
                        goto cleanup;
                    if ((delta->offadj_elems[j] & INT32_MIN) != 0)
                        delta->offadj_elems[j] = TWOS_COMPLEMENT(delta->offadj_elems[j] ^ INT32_MIN);
                }
            }

            printf("offset adjustment elements (%u):", delta->offadj_elems_count);
            for (uint32_t i = 0; i < delta->offadj_elems_count; i++)
                printf(" [%u,%d]", delta->offadj_elems[2 * i], (int32_t)delta->offadj_elems[2 * i + 1]);
            printf("\n");
        }
    }

    if (delta->tgt_header_len == 0 && delta->type == DRPM_TYPE_RPMONLY) {
        error = DRPM_ERR_FORMAT;
        goto cleanup;
    }

    if ((error = decompstrm_read_be32(stream, &delta->tgt_leadsig_len)) != DRPM_ERR_OK)
        goto cleanup;

    if (delta->tgt_leadsig_len < RPM_LEADSIG_MIN_LEN) {
        error = DRPM_ERR_FORMAT;
        goto cleanup;
    }

    if ((delta->tgt_leadsig = malloc(delta->tgt_leadsig_len)) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup;
    }

    if ((error = decompstrm_read(stream, delta->tgt_leadsig_len, delta->tgt_leadsig)) != DRPM_ERR_OK)
        goto cleanup;

    char leadsig[51];
    dump_hex(leadsig, delta->tgt_leadsig, 25);
    printf("target lead (%u): %s...\n", delta->tgt_leadsig_len, leadsig);

    if ((error = decompstrm_read_be32(stream, &delta->payload_fmt_off)) != DRPM_ERR_OK ||
        (error = decompstrm_read_be32(stream, &delta->int_copies_count)) != DRPM_ERR_OK ||
        (error = decompstrm_read_be32(stream, &delta->ext_copies_count)) != DRPM_ERR_OK)
        goto cleanup;

    printf("payload format offset: %u\n", delta->payload_fmt_off);

    int_copies_size = delta->int_copies_count * 2;
    ext_copies_size = delta->ext_copies_count * 2;

    if (int_copies_size > 0) {
        if ((delta->int_copies = malloc(int_copies_size * 4)) == NULL) {
            error = DRPM_ERR_MEMORY;
            goto cleanup;
        }
        for (uint32_t i = 0; i < int_copies_size; i += 2)
            if ((error = decompstrm_read_be32(stream, delta->int_copies + i)) != DRPM_ERR_OK)
                goto cleanup;
        for (uint32_t j = 1; j < int_copies_size; j += 2)
            if ((error = decompstrm_read_be32(stream, delta->int_copies + j)) != DRPM_ERR_OK)
                goto cleanup;
    }

    printf("internal copies (%u):", delta->int_copies_count);
    for (uint32_t i = 0; i < delta->int_copies_count; i++)
        printf(" [%u,%u]", delta->int_copies[2 * i], delta->int_copies[2 * i + 1]);
    printf("\n");

    if (ext_copies_size > 0) {
        if ((delta->ext_copies = malloc(ext_copies_size * 4)) == NULL) {
            error = DRPM_ERR_MEMORY;
            goto cleanup;
        }
        for (uint32_t i = 0; i < ext_copies_size; i += 2) {
            if ((error = decompstrm_read_be32(stream, delta->ext_copies + i)) != DRPM_ERR_OK)
                goto cleanup;
            if ((delta->ext_copies[i] & INT32_MIN) != 0)
                delta->ext_copies[i] = TWOS_COMPLEMENT(delta->ext_copies[i] ^ INT32_MIN);
        }
        for (uint32_t j = 1; j < ext_copies_size; j += 2)
            if ((error = decompstrm_read_be32(stream, delta->ext_copies + j)) != DRPM_ERR_OK)
                goto cleanup;
    }

    printf("external copies (%u):", delta->ext_copies_count);
    for (uint32_t i = 0; i < delta->ext_copies_count; i++)
        printf(" [%d,%u]", (int32_t)delta->ext_copies[2 * i], delta->ext_copies[2 * i + 1]);
    printf("\n");

    if (delta->version == 3) {
        if ((error = decompstrm_read_be64(stream, &delta->ext_data_len)) != DRPM_ERR_OK)
            goto cleanup;
    } else {
        if ((error = decompstrm_read_be32(stream, &ext_data_32)) != DRPM_ERR_OK)
            goto cleanup;
        delta->ext_data_len = ext_data_32;
    }

    printf("length of external data: %lu\n", delta->ext_data_len);

    if ((error = decompstrm_read_be32(stream, &delta->add_data_len)) != DRPM_ERR_OK)
        goto cleanup;

    printf("length of add data: %u\n", delta->add_data_len);

    if (delta->add_data_len > 0) {
        if (delta->type == DRPM_TYPE_RPMONLY) {
            error = DRPM_ERR_FORMAT;
            goto cleanup;
        }
        if ((error = decompstrm_read(stream, delta->add_data_len, delta->add_data)) != DRPM_ERR_OK)
            goto cleanup;
    }

    if (delta->version == 3) {
        if ((error = decompstrm_read_be64(stream, &delta->int_data_len)) != DRPM_ERR_OK)
            goto cleanup;
    } else {
        if ((error = decompstrm_read_be32(stream, &int_data_32)) != DRPM_ERR_OK)
            goto cleanup;
        delta->int_data_len = int_data_32;
    }

    printf("length of internal data: %lu\n", delta->int_data_len);

    if (delta->int_data_len > SIZE_MAX) {
        error = DRPM_ERR_OVERFLOW;
        goto cleanup;
    }

    if (delta->int_data_len > 0 && (error = decompstrm_read(stream, delta->int_data_len, delta->int_data.bytes)) != DRPM_ERR_OK)
        goto cleanup;

    delta->int_data_as_ptrs = false;

    off = 0;
    for (uint32_t i = 1; i < int_copies_size; i += 2) {
        off += delta->int_copies[i];
        if (off > delta->int_data_len) {
            error = DRPM_ERR_FORMAT;
            goto cleanup;
        }
    }

    off = 0;
    for (uint32_t i = 0; i < ext_copies_size; i += 2) {
        off += (int32_t)delta->ext_copies[i];
        if (off > delta->ext_data_len) {
            error = DRPM_ERR_FORMAT;
            goto cleanup;
        }
        off += delta->ext_copies[i + 1];
        if (off == 0 || off > delta->ext_data_len) {
            error = DRPM_ERR_FORMAT;
            goto cleanup;
        }
    }

cleanup:
    decompstrm_destroy(&stream);

    return error;
}

int readdelta_rpmonly(int filedesc, struct deltarpm *delta)
{
    uint32_t version;
    uint32_t tgt_nevr_len;
    ssize_t bytes_read;
    int error;

    if ((error = read_be32(filedesc, &version)) != DRPM_ERR_OK)
        return error;

    if (!MAGIC_DLT3(version))
        return DRPM_ERR_FORMAT;

    if ((error = read_be32(filedesc, &tgt_nevr_len)) != DRPM_ERR_OK)
        return error;

    if ((delta->head.tgt_nevr = malloc(tgt_nevr_len + 1)) == NULL)
        return DRPM_ERR_MEMORY;

    if ((bytes_read = read(filedesc, delta->head.tgt_nevr, tgt_nevr_len)) < 0)
        return DRPM_ERR_IO;

    if ((uint32_t)bytes_read != tgt_nevr_len)
        return DRPM_ERR_FORMAT;

    delta->head.tgt_nevr[tgt_nevr_len] = '\0';

    printf("target NEVR: %s\n", delta->head.tgt_nevr);

    if ((error = read_be32(filedesc, &delta->add_data_len)) != DRPM_ERR_OK)
        return error;

    if ((delta->add_data = malloc(delta->add_data_len)) == NULL)
        return DRPM_ERR_MEMORY;

    if ((bytes_read = read(filedesc, delta->add_data, delta->add_data_len)) < 0)
        return DRPM_ERR_IO;

    if ((uint32_t)bytes_read != delta->add_data_len)
        return DRPM_ERR_FORMAT;

    printf("length of add data: %u\n", delta->add_data_len);

    return DRPM_ERR_OK;
}

int readdelta_standard(int filedesc, struct deltarpm *delta)
{
    struct rpm *rpmst;
    int error;

    if ((error = rpm_read(&rpmst, delta->filename, RPM_ARCHIVE_DONT_READ, NULL, NULL, NULL)) != DRPM_ERR_OK)
        return error;

    if ((error = rpm_get_comp(rpmst, &delta->tgt_comp)) != DRPM_ERR_OK)
        return error;

    printf("target compression: %s\n", comp2str(delta->tgt_comp));

    char *tgt_nevr;
    if ((error = rpm_get_nevr(rpmst, &tgt_nevr)) != DRPM_ERR_OK)
        return error;
    printf("target NEVR: %s\n", tgt_nevr);
    free(tgt_nevr);

    if (lseek(filedesc, rpm_size_full(rpmst), SEEK_SET) == (off_t)-1)
        return DRPM_ERR_IO;

    delta->head.tgt_rpm = rpmst;

    return DRPM_ERR_OK;
}

int read_deltarpm(struct deltarpm *delta, const char *filename)
{
    int filedesc;
    uint32_t magic;
    int error = DRPM_ERR_OK;

    if (filename == NULL || delta == NULL)
        return DRPM_ERR_PROG;

    if ((filedesc = open(filename, O_RDONLY)) == -1)
        return DRPM_ERR_IO;

    delta->filename = filename;

    if ((error = read_be32(filedesc, &magic)) != DRPM_ERR_OK)
        goto cleanup_fail;

    switch (magic) {
    case MAGIC_DRPM:
        printf("deltarpm type: rpm-only\n");
        delta->type = DRPM_TYPE_RPMONLY;
        if ((error = readdelta_rpmonly(filedesc, delta)) != DRPM_ERR_OK)
            goto cleanup_fail;
        break;
    case MAGIC_RPM:
        printf("deltarpm type: standard\n");
        delta->type = DRPM_TYPE_STANDARD;
        if ((error = readdelta_standard(filedesc, delta)) != DRPM_ERR_OK)
            goto cleanup_fail;
        break;
    default:
        error = DRPM_ERR_FORMAT;
        goto cleanup_fail;
    }

    if ((error = readdelta_rest(filedesc, delta)) != DRPM_ERR_OK)
        goto cleanup_fail;

    goto cleanup;

cleanup_fail:
    free_deltarpm(delta);

cleanup:
    close(filedesc);

    return error;
}

int deltarpm_to_drpm(const struct deltarpm *src, struct drpm *dst)
{
    const struct drpm init = {0};
    int error;

    if (src == NULL || dst == NULL)
        return DRPM_ERR_PROG;

    *dst = init;

    dst->version = src->version;
    dst->type = src->type;
    dst->comp = src->comp;
    dst->tgt_size = src->tgt_size;
    dst->tgt_comp = src->tgt_comp;
    dst->tgt_header_len = src->tgt_header_len;
    dst->payload_fmt_off = src->payload_fmt_off;
    dst->ext_data_len = src->ext_data_len;
    dst->int_data_len = src->int_data_len;

    dst->offadj_elems_size = src->offadj_elems_count * 2;
    dst->int_copies_size = src->int_copies_count * 2;
    dst->ext_copies_size = src->ext_copies_count * 2;

    if ((dst->filename = malloc(strlen(src->filename) + 1)) == NULL ||
        (dst->sequence = malloc(src->sequence_len * 2 + 1)) == NULL ||
        (dst->src_nevr = malloc(strlen(src->src_nevr) + 1)) == NULL ||
        (src->tgt_comp_param_len > 0 &&
         (dst->tgt_comp_param = malloc(src->tgt_comp_param_len * 2 + 1)) == NULL) ||
        (dst->tgt_leadsig = malloc(src->tgt_leadsig_len * 2 + 1)) == NULL ||
        (dst->offadj_elems_size > 0 &&
         (dst->offadj_elems = malloc(dst->offadj_elems_size * 4)) == NULL) ||
        (dst->int_copies_size > 0 &&
         (dst->int_copies = malloc(dst->int_copies_size * 4)) == NULL) ||
        (dst->ext_copies_size > 0 &&
         (dst->ext_copies = malloc(dst->ext_copies_size * 4)) == NULL)) {
        error = DRPM_ERR_MEMORY;
        goto cleanup_fail;
    }

    strcpy(dst->filename, src->filename);
    strcpy(dst->src_nevr, src->src_nevr);

    dump_hex(dst->sequence, src->sequence, src->sequence_len);
    dump_hex(dst->tgt_md5, src->tgt_md5, MD5_DIGEST_LENGTH);
    dump_hex(dst->tgt_leadsig, src->tgt_leadsig, src->tgt_leadsig_len);
    if (src->tgt_comp_param_len > 0)
        dump_hex(dst->tgt_comp_param, src->tgt_comp_param, src->tgt_comp_param_len);

    if (dst->offadj_elems_size > 0)
        memcpy(dst->offadj_elems, src->offadj_elems, dst->offadj_elems_size * 4);
    if (dst->int_copies_size > 0)
        memcpy(dst->int_copies, src->int_copies, dst->int_copies_size * 4);
    if (dst->ext_copies_size > 0)
        memcpy(dst->ext_copies, src->ext_copies, dst->ext_copies_size * 4);

    if (src->type == DRPM_TYPE_STANDARD && (error = rpm_get_nevr(src->head.tgt_rpm, &dst->tgt_nevr)) != DRPM_ERR_OK)
        goto cleanup_fail;

    return DRPM_ERR_OK;

cleanup_fail:
    drpm_free(dst);

    return error;
}

void drpm_free(struct drpm *delta)
{
    const struct drpm delta_init = {0};

    free(delta->filename);
    free(delta->src_nevr);
    free(delta->tgt_nevr);
    free(delta->sequence);
    free(delta->tgt_comp_param);
    free(delta->tgt_leadsig);
    free(delta->offadj_elems);
    free(delta->int_copies);
    free(delta->ext_copies);

    *delta = delta_init;
}
