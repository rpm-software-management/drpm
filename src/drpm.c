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

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>

#define MAGIC_DRPM 0x6472706D
#define MAGIC_RPM 0xEDABEEDB

#define VERSION_FLAGS (DRPM_FLAG_VERSION_1 | DRPM_FLAG_VERSION_2 \
                       | DRPM_FLAG_VERSION_3)

#define COMP_FLAGS (DRPM_FLAG_COMP_NONE | DRPM_FLAG_COMP_GZIP \
                    | DRPM_FLAG_COMP_BZIP2 | DRPM_FLAG_COMP_LZMA \
                    | DRPM_FLAG_COMP_XZ)

#define COMP_LEVEL_FLAGS (DRPM_FLAG_COMP_LEVEL_1 | DRPM_FLAG_COMP_LEVEL_2 \
                          | DRPM_FLAG_COMP_LEVEL_3 | DRPM_FLAG_COMP_LEVEL_4 \
                          | DRPM_FLAG_COMP_LEVEL_5 | DRPM_FLAG_COMP_LEVEL_6 \
                          | DRPM_FLAG_COMP_LEVEL_7 | DRPM_FLAG_COMP_LEVEL_8 \
                          | DRPM_FLAG_COMP_LEVEL_9)

const char *drpm_strerror(int error)
{
    switch (error) {
    case DRPM_ERR_OK:
        return "no error";
    case DRPM_ERR_MEMORY:
        return "memory allocation error";
    case DRPM_ERR_ARGS:
        return "bad arguments";
    case DRPM_ERR_IO:
        return "I/O error";
    case DRPM_ERR_FORMAT:
        return "wrong file format";
    case DRPM_ERR_CONFIG:
        return "misconfigured external library";
    case DRPM_ERR_OTHER:
        return "unspecified/unknown error";
    case DRPM_ERR_OVERFLOW:
        return "overflow";
    case DRPM_ERR_PROG:
        return "internal programming error";
    default:
        return NULL;
    }
}

int drpm_read(struct drpm **delta_ret, const char *filename)
{
    struct drpm delta = {0};
    int filedesc;
    uint32_t magic;
    int error = DRPM_ERR_OK;

    if (filename == NULL || delta_ret == NULL)
        return DRPM_ERR_ARGS;

    *delta_ret = NULL;

    if ((filedesc = open(filename, O_RDONLY)) == -1)
        return DRPM_ERR_IO;

    if ((delta.filename = malloc(strlen(filename) + 1)) == NULL)
        return DRPM_ERR_MEMORY;

    strcpy(delta.filename, filename);

    if ((error = read_be32(filedesc, &magic)) != DRPM_ERR_OK)
        goto cleanup_fail;

    switch (magic) {
    case MAGIC_DRPM:
        delta.type = DRPM_TYPE_RPMONLY;
        if ((error = readdelta_rpmonly(filedesc, &delta)) != DRPM_ERR_OK)
            goto cleanup_fail;
        break;
    case MAGIC_RPM:
        delta.type = DRPM_TYPE_STANDARD;
        if ((error = readdelta_standard(filedesc, &delta)) != DRPM_ERR_OK)
            goto cleanup_fail;
        break;
    default:
        error = DRPM_ERR_FORMAT;
        goto cleanup_fail;
    }

    if ((error = readdelta_rest(filedesc, &delta)) != DRPM_ERR_OK)
        goto cleanup_fail;

    if ((*delta_ret = malloc(sizeof(struct drpm))) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup_fail;
    }

    **delta_ret = delta;

    goto cleanup;

cleanup_fail:
    free(delta.filename);
    free(delta.src_nevr);
    free(delta.tgt_nevr);
    free(delta.sequence);
    free(delta.tgt_comp_param);
    free(delta.tgt_lead);
    free(delta.adj_elems);
    free(delta.int_copies);
    free(delta.ext_copies);

cleanup:
    close(filedesc);

    return error;
}

int drpm_destroy(struct drpm **delta)
{
    if (delta == NULL || *delta == NULL)
        return DRPM_ERR_ARGS;

    free((*delta)->filename);
    free((*delta)->src_nevr);
    free((*delta)->tgt_nevr);
    free((*delta)->sequence);
    free((*delta)->tgt_comp_param);
    free((*delta)->tgt_lead);
    free((*delta)->adj_elems);
    free((*delta)->int_copies);
    free((*delta)->ext_copies);
    free(*delta);
    *delta = NULL;

    return DRPM_ERR_OK;
}

int drpm_get_uint(struct drpm *delta, int tag, unsigned *ret)
{
    if (delta == NULL || ret == NULL)
        return DRPM_ERR_ARGS;

    switch (tag) {
    case DRPM_TAG_VERSION:
        *ret = (unsigned)delta->version;
        break;
    case DRPM_TAG_TYPE:
        *ret = (unsigned)delta->type;
        break;
    case DRPM_TAG_COMP:
        *ret = (unsigned)delta->comp;
        break;
    case DRPM_TAG_TGTSIZE: // for backward compatibility (possible loss)
        *ret = (unsigned)delta->tgt_size;
        break;
    case DRPM_TAG_TGTCOMP:
        *ret = (unsigned)delta->tgt_comp;
        break;
    default:
        return DRPM_ERR_ARGS;
    }

    return DRPM_ERR_OK;
}

int drpm_get_ulong(struct drpm *delta, int tag, unsigned long *ret)
{
    if (delta == NULL || ret == NULL)
        return DRPM_ERR_ARGS;

    switch (tag) {
    case DRPM_TAG_VERSION:
        *ret = (unsigned long)delta->version;
        break;
    case DRPM_TAG_TYPE:
        *ret = (unsigned long)delta->type;
        break;
    case DRPM_TAG_COMP:
        *ret = (unsigned long)delta->comp;
        break;
    case DRPM_TAG_TGTSIZE:
        *ret = (unsigned long)delta->tgt_size;
        break;
    case DRPM_TAG_TGTCOMP:
        *ret = (unsigned long)delta->tgt_comp;
        break;
    case DRPM_TAG_TGTHEADERLEN:
        *ret = (unsigned long)delta->tgt_header_len;
        break;
    case DRPM_TAG_PAYLOADFMTOFF:
        *ret = (unsigned long)delta->payload_fmt_off;
        break;
    default:
        return DRPM_ERR_ARGS;
    }

    return DRPM_ERR_OK;
}

int drpm_get_ullong(struct drpm *delta, int tag, unsigned long long *ret)
{
    if (delta == NULL || ret == NULL)
        return DRPM_ERR_ARGS;

    switch (tag) {
    case DRPM_TAG_VERSION:
        *ret = (unsigned long long)delta->version;
        break;
    case DRPM_TAG_TYPE:
        *ret = (unsigned long long)delta->type;
        break;
    case DRPM_TAG_COMP:
        *ret = (unsigned long long)delta->comp;
        break;
    case DRPM_TAG_TGTSIZE:
        *ret = (unsigned long long)delta->tgt_size;
        break;
    case DRPM_TAG_TGTCOMP:
        *ret = (unsigned long long)delta->tgt_comp;
        break;
    case DRPM_TAG_TGTHEADERLEN:
        *ret = (unsigned long long)delta->tgt_header_len;
        break;
    case DRPM_TAG_PAYLOADFMTOFF:
        *ret = (unsigned long long)delta->payload_fmt_off;
        break;
    case DRPM_TAG_EXTDATALEN:
        *ret = (unsigned long long)delta->ext_data_len;
        break;
    case DRPM_TAG_INTDATALEN:
        *ret = (unsigned long long)delta->int_data_len;
        break;
    default:
        return DRPM_ERR_ARGS;
    }

    return DRPM_ERR_OK;
}

int drpm_get_string(struct drpm *delta, int tag, char **ret)
{
    char *string;

    if (delta == NULL || ret == NULL)
        return DRPM_ERR_ARGS;

    switch (tag) {
    case DRPM_TAG_FILENAME:
        string = delta->filename;
        break;
    case DRPM_TAG_SEQUENCE:
        string = delta->sequence;
        break;
    case DRPM_TAG_SRCNEVR:
        string = delta->src_nevr;
        break;
    case DRPM_TAG_TGTNEVR:
        string = delta->tgt_nevr;
        break;
    case DRPM_TAG_TGTMD5:
        string = delta->tgt_md5;
        break;
    case DRPM_TAG_TGTCOMPPARAM:
        string = delta->tgt_comp_param;
        break;
    case DRPM_TAG_TGTLEAD:
        string = delta->tgt_lead;
        break;
    default:
        return DRPM_ERR_ARGS;
    }

    if (string == NULL) {
        *ret = NULL;
    } else {
        if ((*ret = malloc(strlen(string) + 1)) == NULL)
            return DRPM_ERR_MEMORY;
        strcpy(*ret, string);
    }

    return DRPM_ERR_OK;
}

int drpm_get_ulong_array(struct drpm *delta, int tag, unsigned long **ret_array, unsigned long *ret_size)
{
    uint32_t *array;

    if (delta == NULL || ret_array == NULL || ret_size == NULL)
        return DRPM_ERR_ARGS;

    switch (tag) {
    case DRPM_TAG_ADJELEMS:
        array = delta->adj_elems;
        *ret_size = (unsigned long)delta->adj_elems_size;
        break;
    case DRPM_TAG_INTCOPIES:
        array = delta->int_copies;
        *ret_size = (unsigned long)delta->int_copies_size;
        break;
    case DRPM_TAG_EXTCOPIES:
        array = delta->ext_copies;
        *ret_size = (unsigned long)delta->ext_copies_size;
        break;
    default:
        return DRPM_ERR_ARGS;
    }

    if (*ret_size == 0) {
        *ret_array = NULL;
    } else {
        if ((*ret_array = malloc(*ret_size * sizeof(unsigned long))) == NULL)
            return DRPM_ERR_MEMORY;

        for (unsigned i = 0; i < *ret_size; i++)
            (*ret_array)[i] = (unsigned long)array[i];
    }

    return DRPM_ERR_OK;
}

int drpm_make(const char *old_rpm_name, const char *new_rpm_name,
              const char *deltarpm_name, const char *seqfile_name, int flags)
{
    int error = DRPM_ERR_OK;

    bool rpm_only;
    bool alone;
    unsigned short version;
    unsigned short comp = USHRT_MAX;
    unsigned short comp_level;
    bool comp_from_rpm = false;

    const char *solo_rpm_name = NULL;
    struct rpm *solo_rpm = NULL;
    struct rpm *old_rpm = NULL;
    struct rpm *new_rpm = NULL;

    unsigned char *old_cpio = NULL;
    size_t old_cpio_len;
    unsigned char *new_cpio = NULL;
    size_t new_cpio_len;

    unsigned char *old_header = NULL;
    uint32_t old_header_len;
    unsigned char *new_header = NULL;
    uint32_t new_header_len;

    unsigned short payload_format;

    struct deltarpm delta = {0};

    if (deltarpm_name == NULL || (old_rpm_name == NULL && new_rpm_name == NULL))
        return DRPM_ERR_ARGS;

    if ((alone = (old_rpm_name == NULL || new_rpm_name == NULL)))
        solo_rpm_name = (old_rpm_name == NULL) ? new_rpm_name : old_rpm_name;

    rpm_only = FLAG_SET(flags, DRPM_FLAG_RPMONLY);

    switch (MASK_FLAGS(flags, VERSION_FLAGS)) {
    case DRPM_FLAG_VERSION_1:
        version = 1;
        break;
    case DRPM_FLAG_VERSION_2:
        version = 2;
        break;
    case DRPM_FLAG_VERSION_3:
    case DRPM_FLAG_NONE:
        version = 3;
        break;
    default:
        return DRPM_ERR_ARGS;
    }

    switch (MASK_FLAGS(flags, COMP_FLAGS)) {
    case DRPM_FLAG_COMP_NONE:
        comp = DRPM_COMP_NONE;
        break;
    case DRPM_FLAG_COMP_GZIP:
        comp = DRPM_COMP_GZIP;
        break;
    case DRPM_FLAG_COMP_BZIP2:
        comp = DRPM_COMP_BZIP2;
        break;
    case DRPM_FLAG_COMP_LZMA:
        comp = DRPM_COMP_LZMA;
        break;
    case DRPM_FLAG_COMP_XZ:
        comp = DRPM_COMP_XZ;
        break;
    case DRPM_FLAG_NONE:
        comp_from_rpm = true;
        break;
    default:
        return DRPM_ERR_ARGS;
    }

    switch (MASK_FLAGS(flags, COMP_LEVEL_FLAGS)) {
    case DRPM_FLAG_COMP_LEVEL_1:
        comp_level = 1;
        break;
    case DRPM_FLAG_COMP_LEVEL_2:
        comp_level = 2;
        break;
    case DRPM_FLAG_COMP_LEVEL_3:
        comp_level = 3;
        break;
    case DRPM_FLAG_COMP_LEVEL_4:
        comp_level = 4;
        break;
    case DRPM_FLAG_COMP_LEVEL_5:
        comp_level = 5;
        break;
    case DRPM_FLAG_COMP_LEVEL_6:
        comp_level = 6;
        break;
    case DRPM_FLAG_COMP_LEVEL_7:
        comp_level = 7;
        break;
    case DRPM_FLAG_COMP_LEVEL_8:
        comp_level = 8;
        break;
    case DRPM_FLAG_COMP_LEVEL_9:
        comp_level = 9;
        break;
    case DRPM_FLAG_NONE:
        comp_level = COMP_LEVEL_DEFAULT;
        break;
    default:
        return DRPM_ERR_ARGS;
    }

    if (rpm_only && version < 3)
        return DRPM_ERR_ARGS;

    delta.filename = deltarpm_name;
    delta.type = rpm_only ? DRPM_TYPE_RPMONLY : DRPM_TYPE_STANDARD;
    delta.version = version;

    if (!comp_from_rpm) {
        delta.comp = comp;
        delta.comp_level = comp_level;
    }

    if (alone && rpm_only) {
        if ((error = fill_nodiff_deltarpm(&delta, solo_rpm_name, comp_from_rpm)) != DRPM_ERR_OK)
            goto cleanup;
        goto write_files;
    }

    if (alone) {
        if ((error = rpm_read(&solo_rpm, solo_rpm_name, RPM_ARCHIVE_READ_DECOMP,
                              comp_from_rpm ? &delta.comp : NULL, NULL, delta.tgt_md5)) != DRPM_ERR_OK)
            goto cleanup;
    } else {
        if (rpm_only) {
            if ((delta.sequence = malloc(MD5_DIGEST_LENGTH)) == NULL) {
                error = DRPM_ERR_MEMORY;
                goto cleanup;
            }
            delta.sequence_len = MD5_DIGEST_LENGTH;
        }
        if ((error = rpm_read(&old_rpm, old_rpm_name, RPM_ARCHIVE_READ_DECOMP,
                              NULL, rpm_only ? delta.sequence : NULL, NULL)) != DRPM_ERR_OK ||
            (error = rpm_read(&new_rpm, new_rpm_name, RPM_ARCHIVE_READ_DECOMP,
                              comp_from_rpm ? &delta.comp : NULL, NULL, delta.tgt_md5)) != DRPM_ERR_OK)
            goto cleanup;
    }

    if ((error = rpm_get_payload_format(alone ? solo_rpm : new_rpm, &payload_format)) != DRPM_ERR_OK)
        goto cleanup;

    if (payload_format != PAYLOAD_FORMAT_CPIO) { // deltarpm doesn't support xar
        error = DRPM_ERR_FORMAT;
        goto cleanup;
    }

    if (comp_from_rpm) {
        if (delta.comp == DRPM_COMP_LZIP) { // deltarpm doesn't support lzip
            delta.comp = DRPM_COMP_XZ;
            delta.comp_level = COMP_LEVEL_DEFAULT;
        } else if ((error = rpm_get_comp_level(alone ? solo_rpm : new_rpm, &delta.comp_level)) != DRPM_ERR_OK) {
            goto cleanup;
        }
    }

    if (!rpm_only) {
        delta.head.tgt_rpm = alone ? solo_rpm : new_rpm;
        if ((error = rpm_get_payload_format_offset(delta.head.tgt_rpm, &delta.payload_fmt_off)) != DRPM_ERR_OK)
            goto cleanup;
    }

    if ((error = rpm_get_nevr(alone ? solo_rpm : old_rpm, &delta.src_nevr)) != DRPM_ERR_OK ||
        (rpm_only && (error = rpm_get_nevr(new_rpm, &delta.head.tgt_nevr)) != DRPM_ERR_OK))
        goto cleanup;

    delta.tgt_size = rpm_size_full(alone ? solo_rpm : new_rpm);

    if (rpm_only) {
        if ((error = rpm_fetch_header(old_rpm, &old_header, &old_header_len)) != DRPM_ERR_OK ||
            (error = rpm_fetch_header(new_rpm, &new_header, &new_header_len)) != DRPM_ERR_OK ||
            (error = rpm_fetch_archive(old_rpm, &old_cpio, &old_cpio_len)) != DRPM_ERR_OK ||
            (error = rpm_fetch_archive(new_rpm, &new_cpio, &new_cpio_len)) != DRPM_ERR_OK)
            goto cleanup;

        if ((old_cpio = realloc(old_cpio, old_header_len + old_cpio_len)) == NULL ||
            (new_cpio = realloc(old_cpio, new_header_len + new_cpio_len)) == NULL) {
            error = DRPM_ERR_MEMORY;
            goto cleanup;
        }

        memmove(old_cpio + old_header_len, old_cpio, old_cpio_len);
        memmove(new_cpio + new_header_len, new_cpio, new_cpio_len);
        memcpy(old_cpio, old_header, old_header_len);
        memcpy(new_cpio, new_header, new_header_len);
        old_cpio_len += old_header_len;
        new_cpio_len += new_header_len;

        delta.tgt_header_len = new_header_len;
    } else {
        if ((error = parse_cpio_from_rpm_filedata(alone ? solo_rpm : old_rpm,
                                                  &old_cpio, &old_cpio_len,
                                                  &delta.sequence, &delta.sequence_len,
                                                  (version >= 3) ? &delta.offadjs : NULL,
                                                  (version >= 3) ? &delta.offadjn : NULL)) != DRPM_ERR_OK ||
            (error = rpm_fetch_archive(alone ? solo_rpm : new_rpm, &new_cpio, &new_cpio_len)) != DRPM_ERR_OK)
            goto cleanup;
    }

    //...

write_files:
    if ((error = write_deltarpm(&delta)) != DRPM_ERR_OK)
        goto cleanup;

    if (seqfile_name != NULL)
        error = write_seqfile(&delta, seqfile_name);

cleanup:
    free_deltarpm(&delta);

    rpm_destroy(&solo_rpm);
    rpm_destroy(&old_rpm);
    rpm_destroy(&new_rpm);

    free(old_cpio);
    free(new_cpio);
    free(old_header);
    free(new_header);

    return error;
}
