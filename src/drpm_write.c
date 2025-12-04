/*
    Authors:
        Matej Chalk <mchalk@redhat.com>

    Copyright (C) 2015 Red Hat

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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <rpm/rpmlib.h>

/* Wrapper for struct compstrm. Used to prepend uncompressed header. */
struct compstrm_wrapper {
    struct compstrm *strm; // compression stream
    int filedesc; // file descriptor
    size_t uncomp_len; // length of uncompressed data
    size_t uncomp_left; // how much uncompressed data left to write
    unsigned char *uncomp_data; // uncompressed data
};

/* Writes 32-byte integer in network byte order to file. */
int write_be32(int filedesc, uint32_t number)
{
    unsigned char nbo[4];

    create_be32(number, nbo);

    if (write(filedesc, nbo, 4) != 4)
        return DRPM_ERR_IO;

    return DRPM_ERR_OK;
}

/* Writes 64-byte integer in network byte order to file. */
int write_be64(int filedesc, uint64_t number)
{
    unsigned char nbo[8];

    create_be64(number, nbo);

    if (write(filedesc, nbo, 8) != 8)
        return DRPM_ERR_IO;

    return DRPM_ERR_OK;
}

/* Writes out the DeltaRPM. */
int write_deltarpm(struct deltarpm *delta)
{
    int error = DRPM_ERR_OK;
    int filedesc = -1;
    struct compstrm *stream = NULL;
    uint32_t tgt_nevr_len;
    uint32_t src_nevr_len;
    char version[5];
    uint32_t tgt_comp;
    uint32_t int_copies_size;
    uint32_t ext_copies_size;
    unsigned char *header = NULL;
    uint32_t header_size;
    EVP_MD_CTX *md5 = NULL;
    unsigned char md5_digest[MD5_DIGEST_LENGTH] = {0};
    unsigned char *strm_data = NULL;
    size_t strm_data_len;

    if (delta->type != DRPM_TYPE_STANDARD && delta->type != DRPM_TYPE_RPMONLY)
        return DRPM_ERR_PROG;

    version[0] = 'D';
    version[1] = 'L';
    version[2] = 'T';
    version[3] = '0' + delta->version;
    version[4] = '\0';

    src_nevr_len = strlen(delta->src_nevr) + 1;

    if ((error = compstrm_init(&stream, -1, delta->comp, (int)delta->comp_level)) != DRPM_ERR_OK ||
        (error = compstrm_write(stream, 4, version)) != DRPM_ERR_OK ||
        (error = compstrm_write_be32(stream, src_nevr_len)) != DRPM_ERR_OK ||
        (error = compstrm_write(stream, src_nevr_len, delta->src_nevr)) != DRPM_ERR_OK ||
        (error = compstrm_write_be32(stream, delta->sequence_len)) != DRPM_ERR_OK ||
        (error = compstrm_write(stream, delta->sequence_len, delta->sequence)) != DRPM_ERR_OK ||
        (error = compstrm_write(stream, MD5_DIGEST_LENGTH, delta->tgt_md5)) != DRPM_ERR_OK)
        goto cleanup;

    if (delta->version >= 2) {
        if (!deltarpm_encode_comp(&tgt_comp, delta->tgt_comp, delta->tgt_comp_level)) {
            error = DRPM_ERR_PROG;
            goto cleanup;
        }

        if ((error = compstrm_write_be32(stream, delta->tgt_size)) != DRPM_ERR_OK ||
            (error = compstrm_write_be32(stream, tgt_comp)) != DRPM_ERR_OK ||
            (error = compstrm_write_be32(stream, delta->tgt_comp_param_len)) != DRPM_ERR_OK ||
            (error = compstrm_write(stream, delta->tgt_comp_param_len, delta->tgt_comp_param)) != DRPM_ERR_OK)
            goto cleanup;

        if (delta->version >= 3) {
            if ((error = compstrm_write_be32(stream, delta->tgt_header_len)) != DRPM_ERR_OK ||
                (error = compstrm_write_be32(stream, delta->offadj_elems_count)) != DRPM_ERR_OK)
                goto cleanup;

            /* offadj_elems and later int_copies and ext_copies are all pairs of numbers,
             * so in order to get the actual size we mupliply their count by 2.
             * We start with only even elements to store just the first numbers from pairs together
             * and then come all the second numbers together.*/
            uint32_t offadj_elems_size = delta->offadj_elems_count * 2;
            for (uint32_t i = 0; i < offadj_elems_size; i += 2) {
                if ((error = compstrm_write_be32(stream, delta->offadj_elems[i])) != DRPM_ERR_OK)
                    goto cleanup;
            }
            for (uint32_t j = 1; j < offadj_elems_size; j += 2) {
                if ((error = compstrm_write_be32(stream, (int32_t)delta->offadj_elems[j] < 0 ?
                                                         TWOS_COMPLEMENT(delta->offadj_elems[j]) | INT32_MIN :
                                                         delta->offadj_elems[j])) != DRPM_ERR_OK)
                    goto cleanup;
            }
        }
    }

    if ((error = compstrm_write_be32(stream, delta->tgt_leadsig_len)) != DRPM_ERR_OK ||
        (error = compstrm_write(stream, delta->tgt_leadsig_len, delta->tgt_leadsig)) != DRPM_ERR_OK ||
        (error = compstrm_write_be32(stream, delta->payload_fmt_off)) != DRPM_ERR_OK ||
        (error = compstrm_write_be32(stream, delta->int_copies_count)) != DRPM_ERR_OK ||
        (error = compstrm_write_be32(stream, delta->ext_copies_count)) != DRPM_ERR_OK)
        goto cleanup;

    int_copies_size = delta->int_copies_count * 2;
    ext_copies_size = delta->ext_copies_count * 2;

    for (uint32_t i = 0; i < int_copies_size; i += 2) {
        if ((error = compstrm_write_be32(stream, delta->int_copies[i])) != DRPM_ERR_OK)
            goto cleanup;
    }
    for (uint32_t j = 1; j < int_copies_size; j += 2) {
        if ((error = compstrm_write_be32(stream, delta->int_copies[j])) != DRPM_ERR_OK)
            goto cleanup;
    }

    for (uint32_t i = 0; i < ext_copies_size; i += 2) {
        if ((error = compstrm_write_be32(stream, (int32_t)delta->ext_copies[i] < 0 ?
                                                 TWOS_COMPLEMENT(delta->ext_copies[i]) | INT32_MIN :
                                                 delta->ext_copies[i])) != DRPM_ERR_OK)
            goto cleanup;
    }
    for (uint32_t j = 1; j < ext_copies_size; j += 2) {
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

    if (delta->int_data_as_ptrs) {
        for (uint32_t i = 0; i < delta->int_copies_count; i++) {
            if ((error = compstrm_write(stream, delta->int_copies[i * 2 + 1],
                                                delta->int_data.ptrs[i])) != DRPM_ERR_OK)
                goto cleanup;
        }
    } else {
        if ((error = compstrm_write(stream, delta->int_data_len, delta->int_data.bytes)) != DRPM_ERR_OK)
            goto cleanup;
    }

    if ((error = compstrm_finish(stream, &strm_data, &strm_data_len)) != DRPM_ERR_OK)
        goto cleanup;

    switch (delta->type) {
    case DRPM_TYPE_STANDARD:
        if ((error = rpm_fetch_header(delta->head.tgt_rpm, &header, &header_size)) != DRPM_ERR_OK)
            return error;

        if ((md5 = EVP_MD_CTX_new(), md5 == NULL) ||
            EVP_DigestInit_ex(md5, EVP_md5(), NULL) != 1 ||
            EVP_DigestUpdate(md5, header, header_size) != 1 ||
            EVP_DigestUpdate(md5, strm_data, strm_data_len) != 1 ||
            EVP_DigestFinal_ex(md5, md5_digest, NULL) != 1) {
            if (md5 != NULL)
                EVP_MD_CTX_free(md5);
            return DRPM_ERR_OTHER;
        }
        EVP_MD_CTX_free(md5);

        if ((error = rpm_signature_empty(delta->head.tgt_rpm)) != DRPM_ERR_OK ||
            (error = rpm_signature_set_size(delta->head.tgt_rpm, header_size + strm_data_len)) != DRPM_ERR_OK ||
            (error = rpm_signature_set_md5(delta->head.tgt_rpm, md5_digest)) != DRPM_ERR_OK ||
            (error = rpm_signature_reload(delta->head.tgt_rpm)) != DRPM_ERR_OK ||
            (error = rpm_write(delta->head.tgt_rpm, delta->filename, false, NULL, false)) != DRPM_ERR_OK)
            return error;

        if ((filedesc = open(delta->filename, O_WRONLY | O_APPEND)) < 0)
            return DRPM_ERR_IO;
        break;

    case DRPM_TYPE_RPMONLY:
        if ((filedesc = creat(delta->filename, CREAT_MODE)) < 0)
            return DRPM_ERR_IO;

        if (write(filedesc, "drpm", 4) != 4 ||
            write(filedesc, version, 4) != 4) {
            error = DRPM_ERR_IO;
            goto cleanup;
        }

        tgt_nevr_len = strlen(delta->head.tgt_nevr) + 1;
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
    }

    if (write(filedesc, strm_data, strm_data_len) != (ssize_t)strm_data_len)
        error = DRPM_ERR_IO;

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

/* Wrapper functions for compstrm. Used to prepend uncompressed header. */

int compstrm_wrapper_init(struct compstrm_wrapper **csw, size_t uncomp_len,
                          int filedesc, unsigned short comp, int level)
{
    int error;

    if (csw == NULL || filedesc < 0)
        return DRPM_ERR_PROG;

    if ((*csw = malloc(sizeof(struct compstrm_wrapper))) == NULL ||
        ((*csw)->uncomp_data = malloc(uncomp_len)) == NULL) {
        free(*csw);
        *csw = NULL;
        return DRPM_ERR_MEMORY;
    }

    if ((error = compstrm_init(&(*csw)->strm, filedesc, comp, level)) != DRPM_ERR_OK) {
        free((*csw)->uncomp_data);
        free(*csw);
        *csw = NULL;
        return error;
    }

    (*csw)->filedesc = filedesc;
    (*csw)->uncomp_len = uncomp_len;
    (*csw)->uncomp_left = uncomp_len;

    return DRPM_ERR_OK;
}

int compstrm_wrapper_destroy(struct compstrm_wrapper **csw)
{
    if (csw == NULL || *csw == NULL)
        return DRPM_ERR_PROG;

    compstrm_destroy(&(*csw)->strm);
    free((*csw)->uncomp_data);
    free(*csw);

    return DRPM_ERR_OK;
}

int compstrm_wrapper_write(struct compstrm_wrapper *csw, const unsigned char *buffer, size_t buffer_len)
{
    size_t write_len;

    if (csw == NULL || csw->strm == NULL || csw->filedesc < 0)
        return DRPM_ERR_PROG;

    if (csw->uncomp_left > 0) {
        if (buffer_len == 0)
            return DRPM_ERR_OK;

        if (buffer == NULL)
            return DRPM_ERR_PROG;

        write_len = MIN(csw->uncomp_left, buffer_len);
        if (write(csw->filedesc, buffer, write_len) != (ssize_t)write_len)
            return DRPM_ERR_IO;
        memcpy(csw->uncomp_data + csw->uncomp_len - csw->uncomp_left, buffer, write_len);
        buffer += write_len;
        buffer_len -= write_len;
        csw->uncomp_left -= write_len;
    }

    return compstrm_write(csw->strm, buffer_len, buffer);
}

int compstrm_wrapper_finish(struct compstrm_wrapper *csw, unsigned char **data, size_t *data_len)
{
    int error;
    unsigned char *data_tmp;

    if (csw == NULL)
        return DRPM_ERR_PROG;

    if ((error = compstrm_finish(csw->strm, data, data_len)) != DRPM_ERR_OK)
        return error;

    if ((data_tmp = realloc(*data, csw->uncomp_len + *data_len)) == NULL) {
        free(*data);
        return DRPM_ERR_MEMORY;
    }

    memmove(data_tmp + csw->uncomp_len, data_tmp, *data_len);
    memcpy(data_tmp, csw->uncomp_data, csw->uncomp_len);

    *data = data_tmp;
    *data_len += csw->uncomp_len;

    return DRPM_ERR_OK;
}
