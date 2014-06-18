#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <rpm/rpmlib.h>

#include "drpm.h"
#include "drpm_private.h"

#define MAGIC_DLT(x) (((x) >> 8) == 0x444C54)

int read_be32(int filedesc, uint32_t *buffer_ret)
{
    char buffer[4];

    if (read(filedesc, buffer, 4) != 4)
        return EIO;

    *buffer_ret = parse_be32(buffer);

    return EOK;
}
     
int readdelta_rest(int filedesc, struct drpm *delta)
{
    struct compstrm *stream;
    uint32_t src_nevr_len;
    uint32_t sequence_len;
    char *sequence = NULL;
    char md5[MD5_BYTES];
    int error = EOK;

    if ((error = compstrm_init(&stream, filedesc, &delta->comp)) != EOK)
        return error;

    if ((error = compstrm_read_be32(stream, &delta->version)) != EOK)
        goto cleanup;

    if (!MAGIC_DLT(delta->version)) {
        error = EINVAL;
        goto cleanup;
    }

    delta->version = delta->version % 256 - '0';

    if (delta->version < 3 && delta->type == DRPM_TYPE_RPMONLY) {
        error = EINVAL;
        goto cleanup;
    }

    if ((error = compstrm_read_be32(stream, &src_nevr_len)) != EOK)
        goto cleanup;

    if ((delta->src_nevr = malloc(src_nevr_len + 1)) == NULL) {
        error = ENOMEM;
        goto cleanup;
    }

    if ((error = compstrm_read(stream, src_nevr_len, delta->src_nevr)) != EOK)
        goto cleanup;

    delta->src_nevr[src_nevr_len] = '\0';

    if ((error = compstrm_read_be32(stream, &sequence_len)) != EOK)
        goto cleanup;

    if (sequence_len < MD5_BYTES) {
        error = EINVAL;
        goto cleanup;
    }

    if ((sequence = malloc(sequence_len)) == NULL ||
        (delta->sequence = malloc(sequence_len * 2 + 1)) == NULL) {
        error = ENOMEM;
        goto cleanup;
    }

    if ((error = compstrm_read(stream, sequence_len, sequence)) != EOK)
        goto cleanup;

    dump_hex(delta->sequence, sequence, sequence_len);

    if ((error = compstrm_read(stream, sequence_len - MD5_BYTES, NULL)) != EOK)
        goto cleanup;

    if ((error = compstrm_read(stream, MD5_BYTES, md5)) != EOK)
        goto cleanup;

    dump_hex(delta->tgt_md5, md5, MD5_BYTES);

    if (delta->version < 2) {
        delta->tgt_size = 0;
        goto cleanup;
    }

    error = compstrm_read_be32(stream, &delta->tgt_size);

cleanup:
    compstrm_destroy(&stream);
    free(sequence);

    return error;
}

int readdelta_rpmonly(int filedesc, struct drpm *delta)
{
    uint32_t version;
    uint32_t tgt_nevr_len;
    uint32_t add_data_size;

    if (read_be32(filedesc, &version) != EOK ||
        !MAGIC_DLT(version))
        return EINVAL;

    version = (version & 0x000000FF) - '0';

    if (version < 1 || version > 3 ||
        read_be32(filedesc, &tgt_nevr_len) != EOK)
        return EINVAL;

    if ((delta->tgt_nevr = malloc(tgt_nevr_len + 1)) == NULL)
        return ENOMEM;

    if (read(filedesc, delta->tgt_nevr, tgt_nevr_len) != tgt_nevr_len)
        return EINVAL;

    delta->tgt_nevr[tgt_nevr_len] = '\0';

    if (read_be32(filedesc, &add_data_size) != EOK)
        return EINVAL;

    lseek(filedesc, add_data_size, SEEK_CUR);

    return EOK;
}

int readdelta_standard(int filedesc, struct drpm *delta)
{
    FD_t file;
    Header header;
    Header signature;
    char *name = NULL;
    char *version = NULL;
    char *release = NULL;
    off_t file_pos;

    if ((file = Fopen(delta->filename, "rb")) == NULL)
        return EIO;

    Fseek(file, 96, SEEK_SET);

    if ((signature = headerRead(file, HEADER_MAGIC_YES))
        == NULL)
        return EINVAL;

    if ((file_pos = Ftell(file)) % 8)
        Fseek(file, 8 - (file_pos % 8), SEEK_CUR);

    if ((header = headerRead(file, HEADER_MAGIC_YES))
        == NULL)
        return EINVAL;

    if ((name = headerGetAsString(header, RPMTAG_NAME)) == NULL ||
        (version = headerGetAsString(header, RPMTAG_VERSION)) == NULL ||
        (release = headerGetAsString(header, RPMTAG_RELEASE)) == NULL ||
        (delta->tgt_nevr = malloc(strlen(name) + strlen(version) +
                                  strlen(release) + 3)) == NULL)
        return ENOMEM;
    
    sprintf(delta->tgt_nevr, "%s-%s-%s", name, version, release);
    lseek(filedesc, Ftell(file), SEEK_SET);
    headerFree(header);
    headerFree(signature);
    Fclose(file);

    return EOK;
}
