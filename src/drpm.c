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

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <stddef.h>

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
        return "file too large";
    case DRPM_ERR_PROG:
        return "internal programming error";
    case DRPM_ERR_MISMATCH:
        return "file changed";
    case DRPM_ERR_NOINSTALL:
        return "old RPM not installed";
    default:
        return "(undefined error value)";
    }
}

/***************************** drpm read ******************************/

int drpm_read(struct drpm **delta_ret, const char *filename)
{
    struct deltarpm delta = {0};
    int error = DRPM_ERR_OK;

    if (filename == NULL || delta_ret == NULL)
        return DRPM_ERR_ARGS;

    if ((error = read_deltarpm(&delta, filename)) != DRPM_ERR_OK)
        goto cleanup;

    if ((*delta_ret = malloc(sizeof(struct drpm))) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup;
    }

    if ((error = deltarpm_to_drpm(&delta, *delta_ret)) != DRPM_ERR_OK)
        goto cleanup;

cleanup:
    free_deltarpm(&delta);

    if (error != DRPM_ERR_OK)
        *delta_ret = NULL;

    return error;
}

int drpm_destroy(struct drpm **delta)
{
    if (delta == NULL || *delta == NULL)
        return DRPM_ERR_ARGS;

    drpm_free(*delta);

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
        string = delta->tgt_leadsig;
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
        array = delta->offadj_elems;
        *ret_size = (unsigned long)delta->offadj_elems_size;
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

        for (unsigned long i = 0; i < *ret_size; i++)
            (*ret_array)[i] = (unsigned long)array[i];
    }

    return DRPM_ERR_OK;
}

/***************************** drpm make ******************************/

int drpm_make(const char *old_rpm_name, const char *new_rpm_name,
              const char *deltarpm_name, const drpm_make_options *user_opts)
{
    int error = DRPM_ERR_OK;

    drpm_make_options opts = {0};
    const bool rpm_only = (user_opts != NULL && user_opts->rpm_only);
    const bool alone = (old_rpm_name == NULL || new_rpm_name == NULL);

    const char *solo_rpm_name = NULL;
    struct rpm *solo_rpm = NULL;
    struct rpm *old_rpm = NULL;
    struct rpm *new_rpm = NULL;

    unsigned char *old_cpio = NULL;
    size_t old_cpio_len = 0;
    unsigned char *old_cpio_tmp;
    unsigned char *new_cpio = NULL;
    size_t new_cpio_len = 0;
    unsigned char *new_cpio_tmp;

    unsigned char *old_header = NULL;
    uint32_t old_header_len = 0;
    unsigned char *new_header = NULL;
    uint32_t new_header_len = 0;

    unsigned short payload_format;
    struct rpm_patches *patches = NULL;

    struct deltarpm delta = {0};

    if (deltarpm_name == NULL || (old_rpm_name == NULL && new_rpm_name == NULL))
        return DRPM_ERR_ARGS;

    if (alone)
        solo_rpm_name = (old_rpm_name == NULL) ? new_rpm_name : old_rpm_name;

    if (user_opts == NULL)
        drpm_make_options_defaults(&opts);
    else
        drpm_make_options_copy(&opts, user_opts);

    if (rpm_only && opts.version < 3)
        return DRPM_ERR_ARGS;

    delta.filename = deltarpm_name;
    delta.type = rpm_only ? DRPM_TYPE_RPMONLY : DRPM_TYPE_STANDARD;
    delta.version = opts.version;

    if (!opts.comp_from_rpm) {
        delta.comp = opts.comp;
        delta.comp_level = opts.comp_level;
    }

    /* no diff to perform for identity rpm-only deltarpms */
    if (alone && rpm_only) {
        if ((error = fill_nodiff_deltarpm(&delta, solo_rpm_name, opts.comp_from_rpm)) != DRPM_ERR_OK)
            goto cleanup;
        goto write_files;
    }

    if (!rpm_only && (error = patches_read(opts.oldrpmprint, opts.oldpatchrpm, &patches)) != DRPM_ERR_OK)
        goto cleanup;

    /* reading RPM(s) (also creating MD5 sums and determining compressor from archive) */
    if (alone) {
        if ((error = rpm_read(&solo_rpm, solo_rpm_name, RPM_ARCHIVE_READ_DECOMP,
                              &delta.tgt_comp, NULL, delta.tgt_md5)) != DRPM_ERR_OK)
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
                              &delta.tgt_comp, NULL, delta.tgt_md5)) != DRPM_ERR_OK)
            goto cleanup;
    }

    /* checking if archive is in CPIO format */
    if ((error = rpm_get_payload_format(alone ? solo_rpm : new_rpm, &payload_format)) != DRPM_ERR_OK)
        goto cleanup;
    if (payload_format != RPM_PAYLOAD_FORMAT_CPIO) { // deltarpm doesn't support xar (TODO)
        error = DRPM_ERR_FORMAT;
        goto cleanup;
    }

    /* reading compression level of target RPM */
    if ((error = rpm_get_comp_level(alone ? solo_rpm : new_rpm, &delta.tgt_comp_level)) != DRPM_ERR_OK)
        goto cleanup;

    /* matching RPM compression if no compression specified by user */
    if (opts.comp_from_rpm) {
        delta.comp = delta.tgt_comp;
        delta.comp_level = delta.tgt_comp_level;
    }

    if (!rpm_only)
        delta.head.tgt_rpm = alone ? solo_rpm : new_rpm;

    /* reading source and target NEVRs */
    if ((error = rpm_get_nevr(alone ? solo_rpm : old_rpm, &delta.src_nevr)) != DRPM_ERR_OK ||
        (rpm_only && (error = rpm_get_nevr(new_rpm, &delta.head.tgt_nevr)) != DRPM_ERR_OK))
        goto cleanup;

    if (patches != NULL && (error = patches_check_nevr(patches, delta.src_nevr)) != DRPM_ERR_OK)
        goto cleanup;

    if ((error = rpm_fetch_lead_and_signature(alone ? solo_rpm : new_rpm, &delta.tgt_leadsig, &delta.tgt_leadsig_len)) != DRPM_ERR_OK)
        goto cleanup;

    /* storing size of target RPM file */
    delta.tgt_size = rpm_size_full(alone ? solo_rpm : new_rpm);

    /* creating old_cpio and new_cpio for binary diff */
    if (rpm_only) {
    /* rpm-only deltarpms include RPM headers in diff */
        if ((error = rpm_fetch_header(old_rpm, &old_header, &old_header_len)) != DRPM_ERR_OK ||
            (error = rpm_fetch_header(new_rpm, &new_header, &new_header_len)) != DRPM_ERR_OK ||
            (error = rpm_fetch_archive(old_rpm, &old_cpio, &old_cpio_len)) != DRPM_ERR_OK ||
            (error = rpm_fetch_archive(new_rpm, &new_cpio, &new_cpio_len)) != DRPM_ERR_OK)
            goto cleanup;

        if ((old_cpio_tmp = realloc(old_cpio, old_header_len + old_cpio_len)) == NULL ||
            (new_cpio_tmp = realloc(new_cpio, new_header_len + new_cpio_len)) == NULL) {
            error = DRPM_ERR_MEMORY;
            goto cleanup;
        }
        old_cpio = old_cpio_tmp;
        new_cpio = new_cpio_tmp;

        memmove(old_cpio + old_header_len, old_cpio, old_cpio_len);
        memmove(new_cpio + new_header_len, new_cpio, new_cpio_len);
        memcpy(old_cpio, old_header, old_header_len);
        memcpy(new_cpio, new_header, new_header_len);
        old_cpio_len += old_header_len;
        new_cpio_len += new_header_len;

        /* storing size of target header included in diff */
        delta.tgt_header_len = new_header_len;
    } else {
    /* standard deltarpms parse archive of old RPM based on filesystem data */
        if ((error = parse_cpio_from_rpm_filedata(alone ? solo_rpm : old_rpm,
                                                  &old_cpio, &old_cpio_len,
                                                  &delta.sequence, &delta.sequence_len,
                                                  (delta.version >= 3) ? &delta.offadj_elems : NULL,
                                                  (delta.version >= 3) ? &delta.offadj_elems_count : NULL,
                                                  patches)) != DRPM_ERR_OK ||
            (error = rpm_fetch_archive(alone ? solo_rpm : new_rpm, &new_cpio, &new_cpio_len)) != DRPM_ERR_OK)
            goto cleanup;
    }

    /* patching and storing offset of payload format tag in header for compatibility with deltarpm */
    if ((!rpm_only && (error = rpm_patch_payload_format(delta.head.tgt_rpm, "drpm")) != DRPM_ERR_OK) ||
        (error = rpm_find_payload_format_offset(alone ? solo_rpm : new_rpm, &delta.payload_fmt_off)) != DRPM_ERR_OK)
        goto cleanup;

    /* diff algorithm, creating deltarpm diff data */
    if ((error = make_diff(old_cpio, old_cpio_len, new_cpio, new_cpio_len,
                           &delta.int_data.ptrs, &delta.int_data_len,
                           &delta.ext_copies, &delta.ext_copies_count,
                           &delta.int_copies, &delta.int_copies_count,
                           opts.addblk ? &delta.add_data : NULL, opts.addblk ? &delta.add_data_len : NULL,
                           opts.addblk_comp, opts.addblk_comp_level)) != DRPM_ERR_OK)
        goto cleanup;

    delta.int_data_as_ptrs = true;
    delta.ext_data_len = old_cpio_len;

write_files:

    if ((error = write_deltarpm(&delta)) != DRPM_ERR_OK)
        goto cleanup;

    if (opts.seqfile != NULL)
        error = write_seqfile(&delta, opts.seqfile);

cleanup:

    free_deltarpm(&delta);

    rpm_destroy(&old_rpm);
    if (rpm_only) // preventing double free (delta.head.tgt_rpm)
        rpm_destroy(&new_rpm);

    free(old_cpio);
    free(new_cpio);
    free(old_header);
    free(new_header);

    patches_destroy(&patches);

    free(opts.seqfile);
    free(opts.oldrpmprint);
    free(opts.oldpatchrpm);

    return error;
}

/***************************** drpm apply *****************************/

int drpm_apply(const char *old_rpm_name, const char *deltarpm_name, const char *new_rpm_name)
{
    int error = DRPM_ERR_OK;
    struct deltarpm delta = {0};
    const bool from_rpm = (old_rpm_name != NULL);
    bool rpm_only;
    struct rpm *old_rpm = NULL;
    struct rpm *patched_rpm = NULL;
    unsigned char oldsig_md5[MD5_DIGEST_LENGTH];
    unsigned char newsig_md5[MD5_DIGEST_LENGTH];
    char *old_rpm_nevr = NULL;
    struct file_info *files = NULL;
    size_t file_count = 0;
    unsigned short digest_algo;
    struct cpio_file *cpio_files = NULL;
    size_t cpio_files_len = 0;
    struct blocks *blks = NULL;
    int filedesc;
    MD5_CTX md5;
    unsigned char md5_digest[MD5_DIGEST_LENGTH];
    bool no_full_md5;
    bool has_md5;
    const unsigned char empty_md5[MD5_DIGEST_LENGTH] = {0};
    struct decompstrm *addblk_strm = NULL;
    unsigned char *addblk_buf = NULL;
    unsigned char *buffer = NULL;
    size_t buffer_len;
    unsigned char *header = NULL;
    uint32_t header_size;
    struct compstrm_wrapper *csw = NULL;
    const uint32_t *int_copies;
    uint32_t int_copies_count;
    size_t int_copy_len;
    const unsigned char *int_data;
    const uint32_t *ext_copies;
    uint32_t ext_copies_count;
    size_t ext_copy_len;
    uint64_t ext_offset = 0;
    uint32_t ext_copies_todo;
    size_t ext_copies_done = 0;
    size_t blk_id;
    unsigned char *comp_data = NULL;
    size_t comp_data_len;

    if (deltarpm_name == NULL || new_rpm_name == NULL)
        return DRPM_ERR_ARGS;

    if ((filedesc = creat(new_rpm_name, CREAT_MODE)) < 0)
        return DRPM_ERR_IO;

    /* reading DeltaRPM */
    if ((error = read_deltarpm(&delta, deltarpm_name)) != DRPM_ERR_OK)
        goto cleanup;
    rpm_only = (delta.type == DRPM_TYPE_RPMONLY);
    no_full_md5 = (memcmp(empty_md5, delta.tgt_md5, MD5_DIGEST_LENGTH) == 0);

    if (from_rpm) {
        /* reading old RPM */
        if ((error = rpm_read(&old_rpm, old_rpm_name, RPM_ARCHIVE_READ_DECOMP, NULL, NULL, NULL)) != DRPM_ERR_OK)
            goto cleanup;
        if (rpm_only) {
            /* comparing signature MD5 with DeltaRPM sequence */
            if ((error = rpm_signature_get_md5(old_rpm, oldsig_md5, &has_md5)) != DRPM_ERR_OK)
                goto cleanup;
            if (!has_md5) {
                error = DRPM_ERR_FORMAT;
                goto cleanup;
            }
            if (memcmp(delta.sequence, oldsig_md5, MD5_DIGEST_LENGTH) != 0) {
                error = DRPM_ERR_MISMATCH;
                goto cleanup;
            }
        }
    } else {
        // rpm-only deltarpms do not work from filesystem
        if (rpm_only)
            return DRPM_ERR_ARGS;
        // cannot reconstruct source RPMs from filesystem
        if (rpm_is_sourcerpm(delta.head.tgt_rpm))
            return DRPM_ERR_ARGS;
        /* reading old RPM header from database */
        if ((error = rpm_read_header(&old_rpm, delta.src_nevr, NULL)) != DRPM_ERR_OK)
            goto cleanup;
    }

    /* comparing source NEVRs */
    if ((error = rpm_get_nevr(old_rpm, &old_rpm_nevr)) != DRPM_ERR_OK)
        goto cleanup;
    if (strcmp(delta.src_nevr, old_rpm_nevr) != 0) {
        error = DRPM_ERR_MISMATCH;
        goto cleanup;
    }

    if (!rpm_only) {
        /* expanding sequence */
        if ((error = rpm_get_file_info(old_rpm, &files, &file_count, NULL)) != DRPM_ERR_OK ||
            (error = rpm_get_digest_algo(old_rpm, &digest_algo)) != DRPM_ERR_OK ||
            (error = expand_sequence(&cpio_files, &cpio_files_len,
                                     delta.sequence, delta.sequence_len,
                                     files, file_count, digest_algo,
                                     DRPM_CHECK_NONE)) != DRPM_ERR_OK)
            goto cleanup;
    }

    /* overwriting old RPM's lead and signature with new RPM's */
    patched_rpm = old_rpm;
    if ((error = rpm_replace_lead_and_signature(patched_rpm, delta.tgt_leadsig, delta.tgt_leadsig_len)) != DRPM_ERR_OK)
        goto cleanup;

    if (rpm_only && delta.tgt_comp == DRPM_COMP_NONE &&
        delta.int_copies_count == 0 && delta.ext_copies_count == 0) {
    /* no-diff DeltaRPM, no need for reconstruction */
        if ((error = rpm_write(patched_rpm, new_rpm_name, true, md5_digest, !no_full_md5)) != DRPM_ERR_OK)
            goto cleanup;

        goto final_check;
    }

    /* creating blocks for reading external data */
    if ((error = blocks_create(&blks, delta.ext_data_len, files,
                               cpio_files, cpio_files_len,
                               delta.ext_copies, delta.ext_copies_count,
                               from_rpm ? old_rpm : NULL, rpm_only)) != DRPM_ERR_OK)
        goto cleanup;

    /* setting up add block */
    if (delta.add_data_len > 0) {
        if ((error = decompstrm_init(&addblk_strm, -1, NULL, NULL, delta.add_data, delta.add_data_len)) != DRPM_ERR_OK)
            goto cleanup;
        if ((addblk_buf = malloc(block_size())) == NULL) {
            error = DRPM_ERR_MEMORY;
            goto cleanup;
        }
    }

    if ((buffer = malloc(block_size())) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup;
    }

    if (MD5_Init(&md5) != 1) {
        error = DRPM_ERR_OTHER;
        goto cleanup;
    }

    /* writing lead and signature of new RPM */
    if (write(filedesc, delta.tgt_leadsig, delta.tgt_leadsig_len) != (ssize_t)delta.tgt_leadsig_len) {
        error = DRPM_ERR_IO;
        goto cleanup;
    }
    if (!no_full_md5 && MD5_Update(&md5, delta.tgt_leadsig, delta.tgt_leadsig_len) != 1) {
        error = DRPM_ERR_OTHER;
        goto cleanup;
    }

    if (!rpm_only) {
        /* standard delta -> write out header (rpm-only includes it in diff) */
        if ((error = rpm_patch_payload_format(delta.head.tgt_rpm, "cpio")) != DRPM_ERR_OK ||
            (error = rpm_fetch_header(delta.head.tgt_rpm, &header, &header_size)) != DRPM_ERR_OK)
            goto cleanup;
        if (write(filedesc, header, header_size) != (ssize_t)header_size) {
            error = DRPM_ERR_IO;
            goto cleanup;
        }
        if (MD5_Update(&md5, header, header_size) != 1) {
            error = DRPM_ERR_OTHER;
            goto cleanup;
        }
    }

    /* compression stream wrapper, makes sure header is uncompressed if included */
    if ((error = compstrm_wrapper_init(&csw, delta.tgt_header_len,
                                       filedesc, delta.tgt_comp, delta.tgt_comp_level)) != DRPM_ERR_OK)
        goto cleanup;

    /* reconstructing from diff data */

    int_copies = delta.int_copies;
    int_copies_count = delta.int_copies_count;
    ext_copies = delta.ext_copies;
    ext_copies_count = delta.ext_copies_count;
    int_data = delta.int_data.bytes;

    while (int_copies_count--) {
        ext_copies_todo = *int_copies++;
        if (ext_copies_todo > ext_copies_count) {
            error = DRPM_ERR_FORMAT;
            goto cleanup;
        }

        /* performing X external copies before next internal copy */
        while (ext_copies_todo--) {
            ext_offset += (int32_t)*ext_copies++; // adjusting external offset
            ext_copy_len = *ext_copies++; // length of external copy
            ext_copies_count--;
            blk_id = block_id(ext_offset);

            /* performing external copy */
            while (ext_copy_len > 0) {
                if ((error = blocks_next(blks, buffer, &buffer_len,
                                         ext_offset, ext_copy_len,
                                         ext_copies_done, blk_id)) != DRPM_ERR_OK)
                    goto cleanup;

                /* applying add block */
                if (delta.add_data_len > 0) {
                    if ((error = decompstrm_read(addblk_strm, buffer_len, addblk_buf)) != DRPM_ERR_OK)
                        goto cleanup;
                    for (size_t i = 0; i < buffer_len; i++)
                        buffer[i] += (signed char)addblk_buf[i];
                }

                if ((error = compstrm_wrapper_write(csw, buffer, buffer_len)) != DRPM_ERR_OK)
                    goto cleanup;

                ext_copy_len -= buffer_len;
                ext_offset += buffer_len;
                blk_id++;
            }

            ext_copies_done++;
        }

        int_copy_len = *int_copies++;

        /* performing internal copy */
        if ((error = compstrm_wrapper_write(csw, int_data, int_copy_len)) != DRPM_ERR_OK)
            goto cleanup;
        int_data += int_copy_len;
    }

    if ((error = compstrm_wrapper_finish(csw, &comp_data, &comp_data_len)) != DRPM_ERR_OK)
        goto cleanup;

    /* finalizing MD5 of written data */
    if (MD5_Update(&md5, comp_data, comp_data_len) != 1 ||
        MD5_Final(md5_digest, &md5) != 1) {
        error = DRPM_ERR_OTHER;
        goto cleanup;
    }

final_check:

    if (no_full_md5) {
    /* no target MD5 -> only match checksums of header and archive */
        if ((error = rpm_signature_get_md5(patched_rpm, newsig_md5, &has_md5)) != DRPM_ERR_OK)
            goto cleanup;
        if (has_md5 && memcmp(md5_digest, newsig_md5, MD5_DIGEST_LENGTH) != 0) {
            error = DRPM_ERR_MISMATCH;
            goto cleanup;
        }
    } else {
    /* match full MD5 */
        if (memcmp(md5_digest, delta.tgt_md5, MD5_DIGEST_LENGTH) != 0) {
            error = DRPM_ERR_MISMATCH;
            goto cleanup;
        }
    }

cleanup:

    close(filedesc);

    for (size_t i = 0; i < file_count; i++) {
        free(files[i].name);
        free(files[i].md5);
        free(files[i].linkto);
    }
    free(files);
    free_deltarpm(&delta);
    rpm_destroy(&old_rpm);
    free(old_rpm_nevr);

    blocks_destroy(&blks);
    decompstrm_destroy(&addblk_strm);
    compstrm_wrapper_destroy(&csw);
    free(cpio_files);
    free(addblk_buf);
    free(buffer);
    free(header);
    free(comp_data);

    return error;
}

int drpm_check(const char *deltarpm_name, int check_mode)
{
    int error = DRPM_ERR_OK;
    struct deltarpm delta = {0};
    struct rpm *old_rpm = NULL;
    char *old_rpm_nevr = NULL;
    struct file_info *files = NULL;
    size_t file_count = 0;
    unsigned short digest_algo;

    if (deltarpm_name == NULL ||
        (check_mode != DRPM_CHECK_FILESIZES && check_mode != DRPM_CHECK_FULL))
        return DRPM_ERR_ARGS;

    /* reading DeltaRPM */
    if ((error = read_deltarpm(&delta, deltarpm_name)) != DRPM_ERR_OK)
        goto cleanup;

    /* reading old RPM header from database */
    if ((error = rpm_read_header(&old_rpm, delta.src_nevr, NULL)) != DRPM_ERR_OK)
        goto cleanup;

    /* checking NEVRs */
    if ((error = rpm_get_nevr(old_rpm, &old_rpm_nevr)) != DRPM_ERR_OK)
        goto cleanup;
    if (strcmp(delta.src_nevr, old_rpm_nevr) != 0) {
        error = DRPM_ERR_MISMATCH;
        goto cleanup;
    }

    if (delta.type == DRPM_TYPE_STANDARD) {
        /* expanding sequence, checking files */
        if ((error = rpm_get_file_info(old_rpm, &files, &file_count, NULL)) != DRPM_ERR_OK ||
            (error = rpm_get_digest_algo(old_rpm, &digest_algo)) != DRPM_ERR_OK ||
            (error = expand_sequence(NULL, NULL, delta.sequence, delta.sequence_len,
                                     files, file_count, digest_algo, check_mode)) != DRPM_ERR_OK)
            goto cleanup;
    }

cleanup:

    for (size_t i = 0; i < file_count; i++) {
        free(files[i].name);
        free(files[i].md5);
        free(files[i].linkto);
    }
    free(files);
    free_deltarpm(&delta);
    rpm_destroy(&old_rpm);
    free(old_rpm_nevr);

    return error;
}

int drpm_check_sequence(const char *old_rpm_name, const char *sequence, int check_mode)
{
    int error = DRPM_ERR_OK;
    char *nevr = NULL;
    unsigned char *seq = NULL;
    size_t seq_len;
    char *ptr;
    ptrdiff_t nevr_len;
    struct rpm *old_rpm = NULL;
    unsigned char sigmd5[MD5_DIGEST_LENGTH];
    bool has_md5;
    bool rpm_only;
    char *old_rpm_nevr = NULL;
    struct file_info *files = NULL;
    size_t file_count = 0;
    unsigned short digest_algo;

    if (sequence == NULL ||
        (check_mode != DRPM_CHECK_NONE &&
         check_mode != DRPM_CHECK_FILESIZES &&
         check_mode != DRPM_CHECK_FULL) ||
        (old_rpm_name != NULL && check_mode != DRPM_CHECK_NONE))
        return DRPM_ERR_ARGS;

    /* parsing sequence ID into source NEVR and sequence */

    ptr = strrchr(sequence, '-');
    if (ptr == NULL || ptr == sequence)
        return DRPM_ERR_FORMAT;
    nevr_len = ptr - sequence;
    seq_len = (strlen(++ptr)) / 2;
    if (seq_len < MD5_DIGEST_LENGTH) {
        error = DRPM_ERR_FORMAT;
        goto cleanup;
    }
    if ((nevr = malloc(nevr_len + 1)) == NULL ||
        (seq = malloc(seq_len)) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup;
    }
    strncpy(nevr, sequence, nevr_len);
    nevr[nevr_len] = '\0';
    if (parse_hex(seq, ptr) != (ssize_t)seq_len) {
        error = DRPM_ERR_FORMAT;
        goto cleanup;
    }

    if (old_rpm_name == NULL) {
        /* reading header from database */
        if ((error = rpm_read_header(&old_rpm, nevr, NULL)) != DRPM_ERR_OK)
            goto cleanup;
        rpm_only = false;
    } else {
        /* reading old RPM */
        if ((error = rpm_read(&old_rpm, old_rpm_name, RPM_ARCHIVE_DONT_READ, NULL, NULL, NULL)) != DRPM_ERR_OK ||
            (error = rpm_signature_get_md5(old_rpm, sigmd5, &has_md5)) != DRPM_ERR_OK)
            goto cleanup;
        // determining type of delta
        rpm_only = (seq_len == MD5_DIGEST_LENGTH && has_md5 && memcmp(seq, sigmd5, MD5_DIGEST_LENGTH) == 0);
    }

    /* checking NEVRs */
    if ((error = rpm_get_nevr(old_rpm, &old_rpm_nevr)) != DRPM_ERR_OK)
        goto cleanup;
    if (strcmp(nevr, old_rpm_nevr) != 0) {
        error = DRPM_ERR_MISMATCH;
        goto cleanup;
    }

    if (!rpm_only) {
        /* expanding sequence, checking files */
        if ((error = rpm_get_file_info(old_rpm, &files, &file_count, NULL)) != DRPM_ERR_OK ||
            (error = rpm_get_digest_algo(old_rpm, &digest_algo)) != DRPM_ERR_OK ||
            (error = expand_sequence(NULL, NULL, seq, seq_len, files, file_count, digest_algo, check_mode)) != DRPM_ERR_OK)
            goto cleanup;
    }

cleanup:

    for (size_t i = 0; i < file_count; i++) {
        free(files[i].name);
        free(files[i].md5);
        free(files[i].linkto);
    }
    free(files);
    free(nevr);
    free(seq);
    free(old_rpm_nevr);
    rpm_destroy(&old_rpm);

    return error;
}
