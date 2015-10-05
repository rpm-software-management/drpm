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
#include <fcntl.h>
#include <openssl/md5.h>
#include <rpm/rpmlib.h>

#define MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)

int write_be32(int filedesc, uint32_t number)
{
    unsigned char nbo[4];

    create_be32(number, nbo);

    if (write(filedesc, nbo, 4) != 4)
        return DRPM_ERR_IO;

    return DRPM_ERR_OK;
}

int write_be64(int filedesc, uint64_t number)
{
    unsigned char nbo[8];

    create_be64(number, nbo);

    if (write(filedesc, nbo, 8) != 8)
        return DRPM_ERR_IO;

    return DRPM_ERR_OK;
}

int write_deltarpm(struct deltarpm *delta)
{
    int error = DRPM_ERR_OK;
    int filedesc;
    struct compstrm *stream = NULL;
    uint32_t tgt_nevr_len;
    uint32_t src_nevr_len;
    char version[5];
    uint32_t tgt_comp;
    unsigned char *header = NULL;
    uint32_t header_size;
    MD5_CTX md5;
    unsigned char header_signatures[16] = {0};
    unsigned char md5_digest[MD5_DIGEST_LENGTH] = {0};
    unsigned char *strm_data = NULL;
    size_t strm_data_len;

    version[0] = 'D';
    version[1] = 'L';
    version[2] = 'T';
    version[3] = '0' + delta->version;
    version[4] = '\0';

    switch (delta->type) {
    case DRPM_TYPE_STANDARD:
        if ((error = rpm_fetch_header(delta->head.tgt_rpm, &header, &header_size)) != DRPM_ERR_OK)
            return error;

        if (MD5_Init(&md5) != 1 ||
            MD5_Update(&md5, header, header_size) != 1)
            return DRPM_ERR_OTHER;

        create_be32(RPMTAG_HEADERSIGNATURES, header_signatures);
        create_be32(RPM_BIN_TYPE, header_signatures + 4);
        create_be32((uint32_t)-3*16, header_signatures + 8);
        create_be32(16, header_signatures + 12);

        if ((error = rpm_signature_empty(delta->head.tgt_rpm)) != DRPM_ERR_OK ||
            (error = rpm_signature_set_headersignatures(delta->head.tgt_rpm, header_signatures)) != DRPM_ERR_OK ||
            (error = rpm_signature_set_size(delta->head.tgt_rpm, 0)) != DRPM_ERR_OK ||
            (error = rpm_signature_set_md5(delta->head.tgt_rpm, md5_digest)) != DRPM_ERR_OK ||
            (error = rpm_patch_payload_format(delta->head.tgt_rpm, "drpm")) != DRPM_ERR_OK ||
            (error = rpm_write(delta->head.tgt_rpm, delta->filename, false)) != DRPM_ERR_OK)
            return error;

        if ((filedesc = open(delta->filename, O_WRONLY | O_APPEND)) < 0)
            return DRPM_ERR_IO;
        break;

    case DRPM_TYPE_RPMONLY:
        if ((filedesc = creat(delta->filename, MODE)) < 0)
            return DRPM_ERR_IO;

        if (write(filedesc, "drpm", 4) != 4 ||
            write(filedesc, version, 4) != 4) {
            error = DRPM_ERR_IO;
            goto cleanup;
        }

        tgt_nevr_len = strlen(delta->head.tgt_nevr);
        if ((error = write_be32(filedesc, tgt_nevr_len)) != DRPM_ERR_OK)
            goto cleanup;
        if (write(filedesc, delta->head.tgt_nevr, tgt_nevr_len) != (ssize_t)tgt_nevr_len) {
            error = DRPM_ERR_IO;
            goto cleanup;
        }

        if ((error = write_be32(filedesc, delta->add_data_len)) != DRPM_ERR_OK)
            goto cleanup;
        if (write(filedesc, delta->add_data, delta->add_data_len) != (ssize_t)delta->add_data_len) {
            error = DRPM_ERR_IO;
            goto cleanup;
        }
        break;

    default:
        return DRPM_ERR_FORMAT;   
    }

    src_nevr_len = strlen(delta->src_nevr);

    if ((error = compstrm_init(&stream, filedesc /* or -1? */, delta->comp, (int)delta->comp_level)) != DRPM_ERR_OK ||
        (error = compstrm_write(stream, 4, version)) != DRPM_ERR_OK ||
        (error = compstrm_write_be32(stream, src_nevr_len)) != DRPM_ERR_OK ||
        (error = compstrm_write(stream, src_nevr_len, delta->src_nevr)) != DRPM_ERR_OK ||
        (error = compstrm_write_be32(stream, delta->sequence_len)) != DRPM_ERR_OK ||
        (error = compstrm_write(stream, delta->sequence_len, delta->sequence)) != DRPM_ERR_OK ||
        (error = compstrm_write(stream, MD5_DIGEST_LENGTH, delta->tgt_md5)) != DRPM_ERR_OK)
        goto cleanup;

    if (delta->version >= 2) {
        if ((error = compstrm_write_be32(stream, delta->tgt_size)) != DRPM_ERR_OK ||
            !deltarpm_encode_comp(&tgt_comp, delta->tgt_comp, COMP_LEVEL_DEFAULT) ||
            (error = compstrm_write_be32(stream, tgt_comp)) != DRPM_ERR_OK ||
            (error = compstrm_write_be32(stream, delta->tgt_comp_param_len)) != DRPM_ERR_OK ||
            (error = compstrm_write(stream, delta->tgt_comp_param_len, delta->tgt_comp_param)) != DRPM_ERR_OK)
            goto cleanup;

        if (delta->version >= 3) {
            if ((error = compstrm_write_be32(stream, delta->tgt_header_len)) != DRPM_ERR_OK ||
                (error = compstrm_write_be32(stream, delta->offadjn)) != DRPM_ERR_OK)
                goto cleanup;
            for (uint32_t i = 0; i < delta->offadjn; i += 2) {
                if ((error = compstrm_write_be32(stream, delta->offadjs[i])) != DRPM_ERR_OK)
                    goto cleanup;
            }
            for (uint32_t j = 1; j < delta->offadjn; j += 2) {
                if ((error = compstrm_write_be32(stream, delta->offadjs[j])) != DRPM_ERR_OK)
                    goto cleanup;
            }
        }
    }

    if ((error = compstrm_write_be32(stream, delta->tgt_lead_len)) != DRPM_ERR_OK ||
        (error = compstrm_write(stream, delta->tgt_lead_len, delta->tgt_lead)) != DRPM_ERR_OK ||
        (error = compstrm_write_be32(stream, delta->payload_fmt_off)) != DRPM_ERR_OK ||
        (error = compstrm_write_be32(stream, delta->inn)) != DRPM_ERR_OK ||
        (error = compstrm_write_be32(stream, delta->outn)) != DRPM_ERR_OK)
        goto cleanup;

    for (uint32_t i = 0; i < delta->inn; i += 2) {
        if ((error = compstrm_write_be32(stream, delta->int_copies[i])) != DRPM_ERR_OK)
            goto cleanup;
    }
    for (uint32_t j = 1; j < delta->inn; j += 2) {
        if ((error = compstrm_write_be32(stream, delta->int_copies[j])) != DRPM_ERR_OK)
            goto cleanup;
    }

    for (uint32_t i = 0; i < delta->outn; i += 2) {
        if ((error = compstrm_write_be32(stream, delta->ext_copies[i])) != DRPM_ERR_OK)
            goto cleanup;
    }
    for (uint32_t j = 1; j < delta->outn; j += 2) {
        if ((error = compstrm_write_be32(stream, delta->ext_copies[j])) != DRPM_ERR_OK)
            goto cleanup;
    }

    if (delta->version >= 3) {
        if ((error = compstrm_write_be64(stream, delta->ext_data_len)) != DRPM_ERR_OK)
            goto cleanup;
    } else {
        if ((error = compstrm_write_be32(stream, (uint32_t)delta->ext_data_len)) != DRPM_ERR_OK)
            goto cleanup;
    }

    if (delta->type == DRPM_TYPE_STANDARD) {
        if ((error = compstrm_write_be32(stream, delta->add_data_len)) != DRPM_ERR_OK ||
            (error = compstrm_write(stream, delta->add_data_len, delta->add_data)) != DRPM_ERR_OK)
            goto cleanup;
    } else {
        if ((error = compstrm_write_be32(stream, 0)) != DRPM_ERR_OK)
            goto cleanup;
    }

    if (delta->version >= 3) {
        if ((error = compstrm_write_be64(stream, delta->int_data_len)) != DRPM_ERR_OK)
            goto cleanup;
    } else {
        if ((error = compstrm_write_be32(stream, (uint32_t)delta->int_data_len)) != DRPM_ERR_OK)
            goto cleanup;
    }

    if ((error = compstrm_write(stream, delta->int_data_len, delta->int_data)) != DRPM_ERR_OK)
        goto cleanup;

    if ((error = compstrm_finish(stream, &strm_data, &strm_data_len)) != DRPM_ERR_OK)
        goto cleanup;

    if (delta->type == DRPM_TYPE_STANDARD) {
        if (MD5_Update(&md5, strm_data, strm_data_len) != 1 ||
            MD5_Final(md5_digest, &md5) != 1) {
            error = DRPM_ERR_OTHER;
            goto cleanup;
        }
        if ((error = rpm_signature_set_size(delta->head.tgt_rpm, header_size + strm_data_len) != DRPM_ERR_OK) ||
            (error = rpm_signature_set_md5(delta->head.tgt_rpm, md5_digest) != DRPM_ERR_OK) ||
            /* remove? */(error = rpm_rewrite_signature(delta->head.tgt_rpm, filedesc)) != DRPM_ERR_OK)
            goto cleanup;
    }

//    if (write(filedesc, strm_data, strm_data_len) != (ssize_t)strm_data_len)
//        error = DRPM_ERR_IO;

cleanup:
    if (error == DRPM_ERR_OK)
        error = compstrm_destroy(&stream);
    else
        compstrm_destroy(&stream);

    free(header);
    free(strm_data);
    close(filedesc);

    return error;
}

int write_seqfile(struct deltarpm *delta, const char *filename)
{
    FILE *file;
    char *sequence = NULL;
    int error = DRPM_ERR_OK;

    if ((file = fopen(filename, "w")) == NULL)
        return DRPM_ERR_IO;

    if ((sequence = malloc(delta->sequence_len * 2 + 1)) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup;
    }

    dump_hex(sequence, delta->sequence, delta->sequence_len);

    fprintf(file, "%s-%s\n", delta->src_nevr, sequence);

cleanup:
    free(sequence);
    fclose(file);

    return error;
}
