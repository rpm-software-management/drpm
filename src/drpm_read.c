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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <rpm/rpmlib.h>
#include <netinet/in.h>

#include "drpm.h"
#include "drpm_private.h"

#define MAGIC_DLT(x) (((x) >> 8) == 0x444C54)
#define MAGIC_HEADER(buf) (buf[0] == 0x8E && buf[1] == 0xAD && buf[2] == 0xE8)

int read_be32(int filedesc, uint32_t *buffer_ret)
{
    char buffer[4];

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

int readdelta_rest(int filedesc, struct drpm *delta)
{
    struct compstrm *stream;
    uint32_t src_nevr_len;
    uint32_t sequence_len;
    char *sequence = NULL;
    char md5[MD5_BYTES];
    int error = DRPM_ERR_OK;

    if ((error = compstrm_init(&stream, filedesc, &delta->comp)) != DRPM_ERR_OK)
        return error;

    if ((error = compstrm_read_be32(stream, &delta->version)) != DRPM_ERR_OK)
        goto cleanup;

    if (!MAGIC_DLT(delta->version)) {
        error = DRPM_ERR_FORMAT;
        goto cleanup;
    }

    delta->version = delta->version % 256 - '0';

    if (delta->version < 3 && delta->type == DRPM_TYPE_RPMONLY) {
        error = DRPM_ERR_FORMAT;
        goto cleanup;
    }

    if ((error = compstrm_read_be32(stream, &src_nevr_len)) != DRPM_ERR_OK)
        goto cleanup;

    if ((delta->src_nevr = malloc(src_nevr_len + 1)) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup;
    }

    if ((error = compstrm_read(stream, src_nevr_len, delta->src_nevr)) != DRPM_ERR_OK)
        goto cleanup;

    delta->src_nevr[src_nevr_len] = '\0';

    if ((error = compstrm_read_be32(stream, &sequence_len)) != DRPM_ERR_OK)
        goto cleanup;

    if (sequence_len < MD5_BYTES) {
        error = DRPM_ERR_FORMAT;
        goto cleanup;
    }

    if ((sequence = malloc(sequence_len)) == NULL ||
        (delta->sequence = malloc(sequence_len * 2 + 1)) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup;
    }

    if ((error = compstrm_read(stream, sequence_len, sequence)) != DRPM_ERR_OK)
        goto cleanup;

    dump_hex(delta->sequence, sequence, sequence_len);

    if ((error = compstrm_read(stream, MD5_BYTES, md5)) != DRPM_ERR_OK)
        goto cleanup;

    dump_hex(delta->tgt_md5, md5, MD5_BYTES);

    if (delta->version < 2) {
        delta->tgt_size = 0;
        goto cleanup;
    }

    error = compstrm_read_be32(stream, &delta->tgt_size);

cleanup:

    if (error == DRPM_ERR_OK)
        error = compstrm_destroy(&stream);
    else
        compstrm_destroy(&stream);

    free(sequence);

    return error;
}

int readdelta_rpmonly(int filedesc, struct drpm *delta)
{
    uint32_t version;
    uint32_t tgt_nevr_len;
    uint32_t add_data_size;
    int error;
    ssize_t bytes_read;

    if (read_be32(filedesc, &version) != DRPM_ERR_OK ||
        !MAGIC_DLT(version))
        return DRPM_ERR_FORMAT;

    version = (version & 0x000000FF) - '0';

    if (version < 1 || version > 3 ||
        read_be32(filedesc, &tgt_nevr_len) != DRPM_ERR_OK)
        return DRPM_ERR_FORMAT;

    if ((delta->tgt_nevr = malloc(tgt_nevr_len + 1)) == NULL)
        return DRPM_ERR_MEMORY;

    if ((bytes_read = read(filedesc, delta->tgt_nevr, tgt_nevr_len)) == -1)
        return DRPM_ERR_IO;

    if ((uint32_t) bytes_read != tgt_nevr_len)
        return DRPM_ERR_FORMAT;

    delta->tgt_nevr[tgt_nevr_len] = '\0';

    if ((error = read_be32(filedesc, &add_data_size)) != DRPM_ERR_OK)
        return error;

    lseek(filedesc, add_data_size, SEEK_CUR);

    return DRPM_ERR_OK;
}

int readdelta_standard_readstring(FILE* fp, char **ret, off_t offset)
{
    char c;
    off_t size = 0;

    fseek(fp, offset, SEEK_CUR);

    do {
        if (fread(&c, 1, 1, fp) != 1)
            return ferror(fp) ? DRPM_ERR_IO : DRPM_ERR_FORMAT;
        size++;
    } while (c != '\0');

    if ((*ret = malloc(size)) == NULL)
        return DRPM_ERR_MEMORY;

    fseek(fp, -size, SEEK_CUR);

    if (fread(*ret, size, 1, fp) != 1)
        return DRPM_ERR_IO;

    fseek(fp, -(offset+size), SEEK_CUR);

    return DRPM_ERR_OK;
}

int readdelta_standard(int filedesc, struct drpm *delta)
{
    FILE* fp;
    int error;
    off_t align_off;
    off_t name_off, epoch_off, version_off, release_off, nevr_off;
    name_off = epoch_off = version_off = release_off = nevr_off = -1;

    struct rpmhdrindex {
        uint32_t tag;
        uint32_t type;
        uint32_t offset;
        uint32_t count;
    };

    struct rpmheader {
        unsigned char magic[3];
        unsigned char version;
        char reserved[4];
        uint32_t nindex;
        uint32_t hsize;
        struct rpmhdrindex *indexes;
    } signature, header;

    if ((fp = fopen(delta->filename, "rb")) == NULL)
        return DRPM_ERR_IO;

    fseek(fp, 96, SEEK_SET);

    if (fread(&signature, 16, 1, fp) != 1)
        return ferror(fp) ? DRPM_ERR_IO : DRPM_ERR_FORMAT;
    signature.nindex = ntohl(signature.nindex);
    signature.hsize = ntohl(signature.hsize);

    if (!MAGIC_HEADER(signature.magic))
        return DRPM_ERR_FORMAT;

    fseek(fp, signature.nindex * 16 + signature.hsize, SEEK_CUR);

    if ((align_off = ftell(fp) % 8))
        fseek(fp, 8 - align_off, SEEK_CUR);

    if (fread(&header, 16, 1, fp) != 1)
        return ferror(fp) ? DRPM_ERR_IO : DRPM_ERR_FORMAT;
    header.nindex = ntohl(header.nindex);
    header.hsize = ntohl(header.hsize);

    if (!MAGIC_HEADER(header.magic))
        return DRPM_ERR_FORMAT;

    header.indexes = malloc(sizeof(struct rpmhdrindex) * header.nindex);

    for (uint32_t i = 0; i < header.nindex; i++) {
        if (fread(&(header.indexes[i].tag), 4, 1, fp) != 1 ||
            fread(&(header.indexes[i].type), 4, 1, fp) != 1 ||
            fread(&(header.indexes[i].offset), 4, 1, fp) != 1 ||
            fread(&(header.indexes[i].count), 4, 1, fp) != 1)
            return ferror(fp) ? DRPM_ERR_IO : DRPM_ERR_FORMAT;
        header.indexes[i].tag = htonl(header.indexes[i].tag);
        header.indexes[i].type = htonl(header.indexes[i].type);
        header.indexes[i].offset = htonl(header.indexes[i].offset);
        header.indexes[i].count = htonl(header.indexes[i].count);
        if (header.indexes[i].type == RPM_STRING_TYPE &&
            header.indexes[i].count == 1) {
            switch (header.indexes[i].tag) {
            case RPMTAG_NAME:
                name_off = header.indexes[i].offset;
                break;
            case RPMTAG_EPOCH:
                epoch_off = header.indexes[i].offset;
                break;
            case RPMTAG_VERSION:
                version_off = header.indexes[i].offset;
                break;
            case RPMTAG_RELEASE:
                release_off = header.indexes[i].offset;
                break;
            case RPMTAG_NEVR:
                nevr_off = header.indexes[i].offset;
                break;
            default:
                break;
            }
        }
    }

    if (name_off == -1 || version_off == -1 || release_off == -1)
        return DRPM_ERR_FORMAT;

    if (nevr_off == -1) {
        char *name    = NULL;
        char *epoch   = NULL;
        char *version = NULL;
        char *release = NULL;
        size_t nevr_len;

        if ((error = readdelta_standard_readstring(fp, &name, name_off)) != DRPM_ERR_OK ||
            (epoch_off != -1 && (error = readdelta_standard_readstring(fp, &epoch, epoch_off)) != DRPM_ERR_OK) ||
            (error = readdelta_standard_readstring(fp, &version, version_off)) != DRPM_ERR_OK ||
            (error = readdelta_standard_readstring(fp, &release, release_off)) != DRPM_ERR_OK)
            return error;

        nevr_len = strlen(name) + strlen(version) + strlen(release) + 3;
        if (epoch_off != -1)
            nevr_len += strlen(epoch) + 1;

        if ((delta->tgt_nevr = malloc(nevr_len)) == NULL)
            return DRPM_ERR_MEMORY;

        delta->tgt_nevr[0] = '\0';
        strcat(delta->tgt_nevr, name);
        strcat(delta->tgt_nevr, "-");
        if (epoch_off != -1) {
            strcat(delta->tgt_nevr, epoch);
            strcat(delta->tgt_nevr, ":");
        }
        strcat(delta->tgt_nevr, version);
        strcat(delta->tgt_nevr, "-");
        strcat(delta->tgt_nevr, release);

        free(name);
        free(epoch);
        free(version);
        free(release);
    } else {
        if ((error = readdelta_standard_readstring(fp, &(delta->tgt_nevr), nevr_off)) != DRPM_ERR_OK)
            return error;
    }

    fseek(fp, header.hsize, SEEK_CUR);

    lseek(filedesc, ftell(fp), SEEK_SET);
    free(header.indexes);
    fclose(fp);
    return DRPM_ERR_OK;
}
