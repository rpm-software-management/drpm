#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "drpm.h"
#include "drpm_private.h"

#define MAGIC_DRPM 0x6472706D
#define MAGIC_RPM 0xEDABEEDB

int drpm_destroy(struct drpm **delta)
{
    if (delta == NULL || *delta == NULL)
        return DRPM_ERR_ARGS;

    free((*delta)->filename);
    free((*delta)->src_nevr);
    free((*delta)->tgt_nevr);
    free((*delta)->sequence);
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
    case DRPM_TAG_TGTSIZE:
        *ret = (unsigned)delta->tgt_size;
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
    default:
        return DRPM_ERR_ARGS;
    }

    if ((*ret = malloc(strlen(string) + 1)) == NULL)
        return DRPM_ERR_MEMORY;

    strcpy(*ret, string);

    return DRPM_ERR_OK;
}

int drpm_read(struct drpm **delta_ret, const char *filename)
{
    struct drpm delta = {.filename = NULL, .src_nevr = NULL, .tgt_nevr = NULL,
                         .sequence = NULL};
    int filedesc;
    uint32_t magic;
    int error = DRPM_ERR_OK;

    *delta_ret = NULL;

    if (filename == NULL || delta_ret == NULL)
        return DRPM_ERR_ARGS;

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

cleanup:
    close(filedesc);

    return error;
}

