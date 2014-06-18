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
    if (delta == NULL)
        return EINVAL;

    free((*delta)->filename); 
    free((*delta)->src_nevr);
    free((*delta)->tgt_nevr); 
    free((*delta)->sequence);
    free(*delta);
    *delta = NULL;

    return EOK;
}

int drpm_get_uint(struct drpm *delta, int tag, unsigned *ret)
{
    if (delta == NULL || ret == NULL)
        return EINVAL;

    switch (tag) {
        case DRPM_DELTA_VERSION:
            *ret = (unsigned)delta->version;
            break;
        case DRPM_DELTA_TYPE:
            *ret = (unsigned)delta->type;
            break;
        case DRPM_COMPRESSION:
            *ret = (unsigned)delta->comp;
            break;
        case DRPM_TARGET_SIZE:
            *ret = (unsigned)delta->tgt_size;
            break;
        default:
            return EINVAL;
    }

    return EOK;
}

int drpm_get_string(struct drpm *delta, int tag, char **ret)
{
    char *string;

    if (delta == NULL || ret == NULL)
        return EINVAL;

    switch (tag) {
        case DRPM_FILENAME:
            string = delta->filename;
            break;
        case DRPM_SEQUENCE:
            string = delta->sequence;
            break;
        case DRPM_SOURCE_NEVR:
            string = delta->src_nevr;
            break;
        case DRPM_TARGET_NEVR:
            string = delta->tgt_nevr;
            break;
        case DRPM_TARGET_MD5:
            string = delta->tgt_md5;
            break;
        default:
            return EINVAL;
    }

    if ((*ret = malloc(strlen(string) + 1)) == NULL)
        return ENOMEM;

    strcpy(*ret, string);

    return EOK;
}

int drpm_read(char *filename, struct drpm **delta_ret)
{
    struct drpm delta = {.filename = NULL, .src_nevr = NULL, .tgt_nevr = NULL,
                         .sequence = NULL};
    int filedesc;
    uint32_t magic;
    int error = EOK;

    *delta_ret = NULL;

    if (filename == NULL || delta_ret == NULL)
        return EINVAL;

    if ((filedesc = open(filename, O_RDONLY)) == -1)
        return EIO;

    if ((delta.filename = malloc(strlen(filename) + 1)) == NULL)
        return ENOMEM;

    strcpy(delta.filename, filename);

    if (read_be32(filedesc, &magic) != EOK) {
        error = EINVAL;
        goto cleanup_fail;
    }

    switch (magic) {
        case MAGIC_DRPM:
            delta.type = DRPM_TYPE_RPMONLY;
            if ((error = readdelta_rpmonly(filedesc, &delta)) != EOK)
                goto cleanup_fail;
            break;
        case MAGIC_RPM:
            delta.type = DRPM_TYPE_STANDARD;
            if ((error = readdelta_standard(filedesc, &delta)) != EOK)
                goto cleanup_fail;
            break;
        default:
            error = EINVAL;
            goto cleanup_fail;
    }

    if ((error = readdelta_rest(filedesc, &delta)) != EOK)
        goto cleanup_fail;

    if ((*delta_ret = malloc(sizeof(struct drpm))) == NULL) {
        error = ENOMEM;
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

