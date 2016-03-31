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

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#define __USE_XOPEN 1
#include <sys/stat.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <rpm/rpmfi.h>
#include <rpm/rpmvf.h>
#include <rpm/rpmfc.h>
#include <linux/kdev_t.h>

#define BUFFER_SIZE 4096

#define UNSIGNED_SUM_OVERFLOWS(x,y) ((x) + (y) < (y))

#define IN_LIB_DIR(path) (strstr((path), "lib/") != NULL ||\
                          strstr((path), "lib32/") != NULL ||\
                          strstr((path), "lib64/") != NULL)

#define CPIO_MAGIC "070701"
#define CPIO_TRAILER "TRAILER!!!"
#define CPIO_HEADER_SIZE 110 /* new ASCII format (6B + 8B * 13) */
#define CPIO_PADDING(offset) PADDING((offset), 4)

#define CPIO_ALLOC_SIZE 65536

#define SEQ_INIT {.data = NULL, .index = 0, .alloc_len = 0,\
                  .last_seq_start = 0, .last_seq = -1}
#define SEQ_ALLOC_SIZE 32
#define SEQ_BYTE_LEN(index) (((index) + 1) / 2)

#define MAGIC_RPML 0x52504D4C
#define MAGIC_RPM 0xEDABEEDB

#ifndef RPMFILE_UNPATCHED
#define RPMFILE_UNPATCHED (1 << 10)
#endif

struct cpio_header {
    uint16_t ino;
    uint16_t mode;
    uint16_t uid;
    uint16_t gid;
    uint16_t nlink;
    uint32_t mtime;
    uint32_t filesize;
    uint8_t devmajor;
    uint8_t devminor;
    uint8_t rdevmajor;
    uint8_t rdevminor;
    uint16_t namesize;
};

struct files_seq {
    unsigned char *data;
    size_t index;
    size_t alloc_len;
    size_t last_seq_start;
    ssize_t last_seq;
};

struct patch_file {
    char *name;
    uint16_t mode;
    uint32_t flags;
    unsigned char md5[MD5_DIGEST_LENGTH];
};

struct patch_info {
    char *nevr;
    struct patch_file *files;
    size_t file_count;
};

struct rpm_patches {
    struct patch_info rpmprint;
    struct patch_info patchrpm;
};

static int cpio_extend(unsigned char **, size_t *, const void *, size_t);
static int cpio_header_read(struct cpio_header *, const char *);
static void cpio_header_write(const struct cpio_header *, char *);
static bool is_unpatched(const struct rpm_patches *, const char *, const char *);
static int rpml_get_uint16(int, uint16_t *);
static int rpml_get_uint32(int, uint32_t *);
static int rpml_get_string(int, char **);
static int rpml_get_filename(int, char **, uint32_t *);
static int rpml_skip(int, off_t);
static int seq_add(struct files_seq *, unsigned);
static bool seq_append(struct files_seq *, unsigned);
static int seq_final(struct files_seq *, unsigned char **, size_t *);

bool seq_append(struct files_seq *seq, unsigned val)
{
    size_t len = 1;
    unsigned tmp = val;

    while (tmp >= (1<<3)) {
        tmp >>= 3;
        len++;
    }

    if (SEQ_BYTE_LEN(seq->index + len) > seq->alloc_len) {
        if ((seq->data = realloc(seq->data, seq->alloc_len + SEQ_ALLOC_SIZE)) == NULL)
            return false;
        seq->alloc_len += SEQ_ALLOC_SIZE;
    }

    do {
        if (seq->index % 2 == 0)
            seq->data[seq->index / 2] = ((val & 7) | ((len > 1) ? (1<<3) : 0)) << 4;
        else
            seq->data[seq->index / 2] |= (val & 7) | ((len > 1) ? (1<<3) : 0);
    } while (seq->index++, val >>= 3, --len > 0);

    return true;
}

int seq_add(struct files_seq *seq, unsigned index)
{
    unsigned val;

    if ((ssize_t)index == seq->last_seq + 1) {
        seq->last_seq++;
        return DRPM_ERR_OK;
    }

    val = seq->last_seq - seq->last_seq_start + 1;

    if (val > 0 && !seq_append(seq, val))
        return DRPM_ERR_MEMORY;

    if (seq->last_seq >= 0 && (ssize_t)index > seq->last_seq + 1) {
        if (!seq_append(seq, index - (seq->last_seq + 1)))
            return DRPM_ERR_MEMORY;
    } else {
        if (!seq_append(seq, 0) || !seq_append(seq, index))
            return DRPM_ERR_MEMORY;
    }

    seq->last_seq_start = index;
    seq->last_seq = index;

    return DRPM_ERR_OK;
}

int seq_final(struct files_seq *seq, unsigned char **buffer, size_t *size)
{
    unsigned val = seq->last_seq - seq->last_seq_start + 1;

    if (val > 0 && !seq_append(seq, val))
        return DRPM_ERR_MEMORY;

    *buffer = seq->data;
    *size = SEQ_BYTE_LEN(seq->index);

    return DRPM_ERR_OK;
}

int cpio_extend(unsigned char **cpio, size_t *cpio_len,
                const void *seq, size_t len)
{
    size_t old_cpio_len = *cpio_len;
    size_t new_cpio_len = old_cpio_len + len;
    size_t old_padding = PADDING(old_cpio_len, CPIO_ALLOC_SIZE);
    size_t new_padding = PADDING(new_cpio_len, CPIO_ALLOC_SIZE);
    unsigned char *cpio_tmp;

    if (UNSIGNED_SUM_OVERFLOWS(old_cpio_len, len) ||
        UNSIGNED_SUM_OVERFLOWS(new_cpio_len, new_padding))
        return DRPM_ERR_OVERFLOW;

    if (len > old_padding) {
        if ((cpio_tmp = realloc(*cpio, new_cpio_len + new_padding)) == NULL)
            return DRPM_ERR_MEMORY;
        *cpio = cpio_tmp;
    }

    memcpy(*cpio + old_cpio_len, seq, len);
    *cpio_len = new_cpio_len;

    return DRPM_ERR_OK;
}

int cpio_header_read(struct cpio_header *cpio_hdr,
                     const char buffer[CPIO_HEADER_SIZE + 1])
{
    ssize_t ino_ret;
    ssize_t mode_ret;
    ssize_t uid_ret;
    ssize_t gid_ret;
    ssize_t nlink_ret;
    ssize_t mtime_ret;
    ssize_t filesize_ret;
    ssize_t devmajor_ret;
    ssize_t devminor_ret;
    ssize_t rdevmajor_ret;
    ssize_t rdevminor_ret;
    ssize_t namesize_ret;

    if (strncmp(buffer, CPIO_MAGIC, 6) != 0 ||
        (ino_ret = parse_hexnum((buffer += 6), 8)) < 0 ||
        (mode_ret = parse_hexnum((buffer += 8), 8)) < 0 ||
        (uid_ret = parse_hexnum((buffer += 8), 8)) < 0 ||
        (gid_ret = parse_hexnum((buffer += 8), 8)) < 0 ||
        (nlink_ret = parse_hexnum((buffer += 8), 8)) < 0 ||
        (mtime_ret = parse_hexnum((buffer += 8), 8)) < 0 ||
        (filesize_ret = parse_hexnum((buffer += 8), 8)) < 0 ||
        (devmajor_ret = parse_hexnum((buffer += 8), 8)) < 0 ||
        (devminor_ret = parse_hexnum((buffer += 8), 8)) < 0 ||
        (rdevmajor_ret = parse_hexnum((buffer += 8), 8)) < 0 ||
        (rdevminor_ret = parse_hexnum((buffer += 8), 8)) < 0 ||
        (namesize_ret = parse_hexnum((buffer += 8), 8)) < 0)
        return DRPM_ERR_FORMAT;

    cpio_hdr->ino = ino_ret;
    cpio_hdr->mode = mode_ret;
    cpio_hdr->uid = uid_ret;
    cpio_hdr->gid = gid_ret;
    cpio_hdr->nlink = nlink_ret;
    cpio_hdr->mtime = mtime_ret;
    cpio_hdr->filesize = filesize_ret;
    cpio_hdr->devmajor = devmajor_ret;
    cpio_hdr->devminor = devminor_ret;
    cpio_hdr->rdevmajor = rdevmajor_ret;
    cpio_hdr->rdevminor = rdevminor_ret;
    cpio_hdr->namesize = namesize_ret;

    return DRPM_ERR_OK;
}

void cpio_header_write(const struct cpio_header *cpio_hdr,
                       char buffer[CPIO_HEADER_SIZE + 1])
{
    sprintf(buffer, CPIO_MAGIC
            "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
            cpio_hdr->ino, cpio_hdr->mode, cpio_hdr->uid, cpio_hdr->gid,
            cpio_hdr->nlink, cpio_hdr->mtime, cpio_hdr->filesize,
            cpio_hdr->devmajor, cpio_hdr->devminor, cpio_hdr->rdevmajor,
            cpio_hdr->rdevminor, cpio_hdr->namesize, 0);
}

/* For standard deltarpms, the old RPM's CPIO archive is parsed based
 * on filesystem data found in the RPM header. An altered CPIO archive
 * is created: e.g. some files may be skipped, a symlink's file content
 * is replaced with the name of its target, etc.
 * This is also where the deltarpm sequence is created, consisting of
 * the MD5 sum for the files followed by the encoded order of the files
 * in the RPM header.
 * Additionally (for V3 deltarpms), an array of offset adjustment
 * elements is created, which stores offset differences between
 * entries in the original and altered CPIO archives. */
int parse_cpio_from_rpm_filedata(struct rpm *rpm_file,
                                 unsigned char **cpio_ret, size_t *cpio_len_ret,
                                 unsigned char **sequence_ret, uint32_t *sequence_len_ret,
                                 uint32_t **offadjs_ret, uint32_t *offadjn_ret,
                                 const struct rpm_patches *patches)
{
    int error = DRPM_ERR_OK;

    struct file_info *files = NULL;
    size_t file_count;
    bool file_colors;
    struct file_info file = {0};
    unsigned files_index;

    unsigned short digest_algo;
    unsigned char digest[MAX(MD5_DIGEST_LENGTH, SHA256_DIGEST_LENGTH)] = {0};

    unsigned char *cpio = NULL;
    size_t cpio_len = 0;
    size_t cpio_pos = 0;
    struct cpio_header cpio_hdr;
    const struct cpio_header cpio_hdr_init = {0};
    char cpio_buffer[CPIO_HEADER_SIZE + 1];

    bool offadj;
    uint32_t *offadjs = NULL;
    uint32_t offadjn = 0;
    size_t cpio_len_prev = 0;
    uint64_t offset;

    size_t c_filesize;
    size_t c_namesize;
    const char *name;
    size_t name_len;
    char *name_buffer = NULL;
    size_t name_buffer_len = 0;

    unsigned char *sequence = NULL;
    uint32_t sequence_len;
    MD5_CTX seq_md5;
    unsigned char seq_md5_digest[MD5_DIGEST_LENGTH];
    struct files_seq seq = SEQ_INIT;
    unsigned char *seq_files = NULL;
    size_t seq_files_len;

    unsigned short padding_bytes;
    size_t data_len;
    size_t read_len;
    char buffer[BUFFER_SIZE];

    bool skip;

    if (rpm_file == NULL || cpio_ret == NULL || cpio_len_ret == NULL ||
        sequence_ret == NULL || sequence_len_ret == NULL)
        return DRPM_ERR_PROG;

    *cpio_ret = NULL;
    *cpio_len_ret = 0;
    *sequence_ret = NULL;
    *sequence_len_ret = 0;

    if ((offadj = (offadjs_ret != NULL && offadjn_ret != NULL))) {
        *offadjs_ret = NULL;
        *offadjn_ret = 0;
    }

    if (MD5_Init(&seq_md5) != 1)
        return DRPM_ERR_OTHER;

    if ((error = rpm_get_file_info(rpm_file, &files, &file_count, &file_colors)) != DRPM_ERR_OK ||
        (error = rpm_get_digest_algo(rpm_file, &digest_algo)) != DRPM_ERR_OK)
        goto cleanup_fail;

    rpm_archive_rewind(rpm_file);

    while (true) {

        /* reading CPIO header and pathname */

        if ((error = rpm_archive_read_chunk(rpm_file, cpio_buffer, CPIO_HEADER_SIZE)) != DRPM_ERR_OK)
            goto cleanup_fail;

        if ((error = cpio_header_read(&cpio_hdr, cpio_buffer)) != DRPM_ERR_OK)
            goto cleanup_fail;

        c_filesize = cpio_hdr.filesize;
        c_namesize = cpio_hdr.namesize;

        if (c_namesize > name_buffer_len) {
            if ((name_buffer = realloc(name_buffer, c_namesize)) == NULL) {
                error = DRPM_ERR_MEMORY;
                goto cleanup_fail;
            }
            name_buffer_len = c_namesize;
        }

        if ((error = rpm_archive_read_chunk(rpm_file, name_buffer, c_namesize)) != DRPM_ERR_OK)
            goto cleanup_fail;

        name = name_buffer;

        if (strlen(name) != c_namesize - 1) {
            error = DRPM_ERR_FORMAT;
            goto cleanup_fail;
        }

        /* end of archive? */
        if (strcmp(name, CPIO_TRAILER) == 0)
            break;

        if (strncmp(name, "./", 2) == 0)
            name += 2;

        name_len = strlen(name) + 1;

        padding_bytes = CPIO_PADDING(CPIO_HEADER_SIZE + c_namesize);
        if ((error = rpm_archive_read_chunk(rpm_file, NULL, padding_bytes)) != DRPM_ERR_OK)
            goto cleanup_fail;

        const size_t cpio_hdrname_len = CPIO_HEADER_SIZE + c_namesize + padding_bytes;
        size_t cpio_pos_before_hdrname = cpio_pos;

        cpio_pos += cpio_hdrname_len;

        /* looking up file in RPM header, skipping if not found
         * or if it's a regular file and one of the following occur:
         * - file size missmatch between CPIO and RPM headers
         * - bad file flags
         * - bad verify flags
         * - colored file in non-multilib dir */

        for (files_index = 0; files_index < file_count; files_index++) {
            if (strcmp(name, files[files_index].name +
                             ((files[files_index].name[0] == '/') ? 1 : 0)) == 0)
                break;
        }

        if (!(skip = files_index == file_count)) {
            file = files[files_index];
            cpio_hdr = cpio_hdr_init;

            if (patches != NULL && S_ISREG(file.mode) && is_unpatched(patches, name, file.md5)) {
                skip = true;
            } else if (S_ISREG(file.mode)) {
                skip = (c_filesize != file.size) ||
                       ((file.flags & (RPMFILE_CONFIG | RPMFILE_MISSINGOK | RPMFILE_GHOST)) != 0) ||
                       ((file.verify & VERIFY_MD5) == 0 ||
                        (file.verify & VERIFY_SIZE) == 0) ||
                       (file_colors &&
                        (file.color & (RPMFC_ELF32 | RPMFC_ELF64)) != 0 &&
                        !IN_LIB_DIR(name));
                cpio_hdr.filesize = file.size;
            } else if (S_ISLNK(file.mode)) {
                cpio_hdr.filesize = strlen(file.linkto);
            } else if (S_ISBLK(file.mode) || S_ISCHR(file.mode)) {
                cpio_hdr.rdevmajor = MAJOR(file.rdev);
                cpio_hdr.rdevminor = MINOR(file.rdev);
            }
        }

        if (!skip) {
            cpio_hdr.mode = file.mode;
            cpio_hdr.namesize = name_len + 2; // including "./" prefix
            cpio_hdr.nlink = 1;

            /* offset adjustment */
            if (cpio_len != cpio_pos_before_hdrname) {
                if (offadj) {
                    while (true) {
                        if (!resize32((void **)&offadjs, offadjn * 2, 4)) {
                            error = DRPM_ERR_MEMORY;
                            goto cleanup_fail;
                        }

                        if (cpio_len - cpio_len_prev >= (uint32_t)INT32_MIN) {
                            offadjs[offadjn * 2] = INT32_MAX;
                            offadjs[offadjn * 2 + 1] = 0;
                            offadjn++;
                            cpio_len_prev += INT32_MAX;
                            continue;
                        }

                        offadjs[offadjn * 2] = cpio_len - cpio_len_prev;
                        cpio_len_prev = cpio_len;

                        if (cpio_pos_before_hdrname < cpio_len) {
                            offset = cpio_len - cpio_pos_before_hdrname;
                            if (offset >= (uint32_t)INT32_MIN) {
                                offadjs[offadjn++ * 2 + 1] =
                                    TWOS_COMPLEMENT((uint32_t)INT32_MAX);
                                cpio_pos_before_hdrname += INT32_MAX;
                                continue;
                            }
                            offadjs[offadjn++ * 2 + 1] = TWOS_COMPLEMENT(offset);
                        } else {
                            offset = cpio_pos_before_hdrname - cpio_len;
                            if (offset >= (uint32_t)INT32_MIN) {
                                offadjs[offadjn++ * 2 + 1] = INT32_MAX;
                                cpio_pos_before_hdrname -= INT32_MAX;
                                continue;
                            }
                            offadjs[offadjn++ * 2 + 1] = offset;
                        }

                        break;
                    }
                }
                cpio_pos = cpio_len + cpio_hdrname_len;
            }

            /* adding new entry to cpio, updating MD5 */

            cpio_header_write(&cpio_hdr, cpio_buffer);

            if ((error = cpio_extend(&cpio, &cpio_len, cpio_buffer, CPIO_HEADER_SIZE)) != DRPM_ERR_OK ||
                (error = cpio_extend(&cpio, &cpio_len, "./", 2)) != DRPM_ERR_OK ||
                (error = cpio_extend(&cpio, &cpio_len, name, name_len)) != DRPM_ERR_OK ||
                (error = cpio_extend(&cpio, &cpio_len, "\0\0\0",
                                     CPIO_PADDING(CPIO_HEADER_SIZE + cpio_hdr.namesize))) != DRPM_ERR_OK)
                goto cleanup_fail;

            if (MD5_Update(&seq_md5, name, name_len) != 1 ||
                md5_update_be32(&seq_md5, cpio_hdr.mode) != 1 ||
                md5_update_be32(&seq_md5, cpio_hdr.filesize) != 1 ||
                md5_update_be32(&seq_md5, MKDEV(cpio_hdr.rdevmajor,
                                                cpio_hdr.rdevminor)) != 1) {
                error = DRPM_ERR_OTHER;
                goto cleanup_fail;
            }

            if (S_ISLNK(file.mode)) {
                if ((error = cpio_extend(&cpio, &cpio_len, file.linkto, cpio_hdr.filesize)) != DRPM_ERR_OK ||
                    (error = cpio_extend(&cpio, &cpio_len, "\0\0\0", CPIO_PADDING(cpio_hdr.filesize))) != DRPM_ERR_OK)
                    goto cleanup_fail;
                if (MD5_Update(&seq_md5, file.linkto, cpio_hdr.filesize + 1) != 1) {
                    error = DRPM_ERR_OTHER;
                    goto cleanup_fail;
                }
            } else if (S_ISREG(file.mode) && cpio_hdr.filesize) {
                switch (digest_algo) {
                case DIGESTALGO_MD5:
                    if (!parse_md5(digest, file.md5)) {
                        error = DRPM_ERR_FORMAT;
                        goto cleanup_fail;
                    }
                    if (MD5_Update(&seq_md5, digest, MD5_DIGEST_LENGTH) != 1) {
                        error = DRPM_ERR_OTHER;
                        goto cleanup_fail;
                    }
                    break;
                case DIGESTALGO_SHA256:
                    if (!parse_sha256(digest, file.md5)) {
                        error = DRPM_ERR_FORMAT;
                        goto cleanup_fail;
                    }
                    if (MD5_Update(&seq_md5, digest, SHA256_DIGEST_LENGTH) != 1) {
                        error = DRPM_ERR_OTHER;
                        goto cleanup_fail;
                    }
                    break;
                }
            }

            /* adding file index to sequence */
            if ((error = seq_add(&seq, files_index)) != DRPM_ERR_OK)
                goto cleanup_fail;
        }

        /* reading file data and copying to cpio */

        data_len = c_filesize;
        while (data_len > 0) {
            read_len = MIN(data_len, BUFFER_SIZE);
            if ((error = rpm_archive_read_chunk(rpm_file, buffer, read_len)) != DRPM_ERR_OK)
                goto cleanup_fail;
            cpio_pos += read_len;
            if (!S_ISLNK(file.mode) &&
                (error = cpio_extend(&cpio, &cpio_len, buffer, read_len)) != DRPM_ERR_OK)
                goto cleanup_fail;
            data_len -= read_len;
        }

        if ((padding_bytes = CPIO_PADDING(c_filesize)) > 0) {
            if ((error = rpm_archive_read_chunk(rpm_file, NULL, padding_bytes)) != DRPM_ERR_OK)
                goto cleanup_fail;
            cpio_pos += padding_bytes;
            if (!S_ISLNK(file.mode) &&
                (error = cpio_extend(&cpio, &cpio_len, "\0\0\0", padding_bytes)) != DRPM_ERR_OK)
                goto cleanup_fail;
        }
    }

    /* writing CPIO trailer */

    cpio_hdr = cpio_hdr_init;
    cpio_hdr.nlink = 1;
    cpio_hdr.namesize = strlen(CPIO_TRAILER) + 1;

    cpio_header_write(&cpio_hdr, cpio_buffer);

    if ((error = cpio_extend(&cpio, &cpio_len, cpio_buffer, CPIO_HEADER_SIZE)) != DRPM_ERR_OK ||
        (error = cpio_extend(&cpio, &cpio_len, CPIO_TRAILER, cpio_hdr.namesize)) != DRPM_ERR_OK ||
        (error = cpio_extend(&cpio, &cpio_len, "\0\0\0",
                             CPIO_PADDING(CPIO_HEADER_SIZE + cpio_hdr.namesize))) != DRPM_ERR_OK)
        goto cleanup_fail;

    /* completing sequence */

    if ((error = seq_final(&seq, &seq_files, &seq_files_len)) != DRPM_ERR_OK)
        goto cleanup_fail;

    if (MD5_Final(seq_md5_digest, &seq_md5) != 1) {
        error = DRPM_ERR_OTHER;
        goto cleanup_fail;
    }

    sequence_len = MD5_DIGEST_LENGTH + seq_files_len;
    if ((sequence = malloc(sequence_len)) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup_fail;
    }
    memcpy(sequence, seq_md5_digest, MD5_DIGEST_LENGTH);
    memcpy(sequence + MD5_DIGEST_LENGTH, seq_files, seq_files_len);

    *cpio_ret = cpio;
    *cpio_len_ret = cpio_len;
    *sequence_ret = sequence;
    *sequence_len_ret = sequence_len;

    if (offadj) {
        *offadjs_ret = offadjs;
        *offadjn_ret = offadjn;
    }

    goto cleanup;

cleanup_fail:
    free(cpio);
    free(sequence);
    if (offadj)
        free(offadjs);

cleanup:
    for (size_t i = 0; i < file_count; i++) {
        free(files[i].name);
        free(files[i].md5);
        free(files[i].linkto);
    }
    free(files);
    free(name_buffer);
    free(seq_files);

    return error;
}

int rpml_get_uint16(int filedesc, uint16_t *ret)
{
    unsigned char buf[2];

    if (read(filedesc, buf, 2) != 2)
        return DRPM_ERR_FORMAT;

    if (ret != NULL)
        *ret = parse_be16(buf);

    return DRPM_ERR_OK;
}

int rpml_get_uint32(int filedesc, uint32_t *ret)
{
    unsigned char buf[4];

    if (read(filedesc, buf, 4) != 4)
        return DRPM_ERR_FORMAT;

    if (ret != NULL)
        *ret = parse_be32(buf);

    return DRPM_ERR_OK;
}

int rpml_get_string(int filedesc, char **ret)
{
    uint8_t len;

    if (read(filedesc, &len, 1) != 1)
        return DRPM_ERR_FORMAT;

    if (ret != NULL) {
        if ((*ret = malloc(len + 1)) == NULL)
            return DRPM_ERR_MEMORY;
        if (read(filedesc, *ret, len) != len) {
            free(*ret);
            return DRPM_ERR_FORMAT;
        }
        (*ret)[len] = '\0';
    }

    return DRPM_ERR_OK;
}

int rpml_get_filename(int filedesc, char **filename_ret, uint32_t *filename_len_ret)
{
    int error;
    uint8_t off;
    uint16_t len;
    uint8_t buf[2];
    char *filename;
    uint32_t filename_len;
    uint32_t new_filename_len;

    if (filename_ret == NULL || filename_len_ret == NULL)
        return DRPM_ERR_PROG;

    filename = *filename_ret;
    filename_len = *filename_len_ret;

    if (read(filedesc, buf, 2) != 2)
        return DRPM_ERR_FORMAT;

    off = buf[0];

    if (buf[1] == 0xFF) {
        if ((error = rpml_get_uint16(filedesc, &len)) != DRPM_ERR_OK)
            return error;
    } else {
        len = buf[1];
    }

    new_filename_len = off + len + 1;

    if (new_filename_len > filename_len) {
        if ((filename = realloc(filename, new_filename_len)) == NULL)
            return DRPM_ERR_MEMORY;
        filename_len = new_filename_len;
    }

    if (read(filedesc, filename + off, len) != len)
        return DRPM_ERR_FORMAT;

    filename[off + len] = '\0';

    *filename_ret = filename;
    *filename_len_ret = filename_len;

    return DRPM_ERR_OK;
}

int rpml_skip(int filedesc, off_t len)
{
    return lseek(filedesc, len, SEEK_CUR) != (off_t)-1 ?
           DRPM_ERR_OK :
           DRPM_ERR_IO;
}

int read_rpmlist(int filedesc, struct patch_info *patch, bool skip_magic)
{
    int error = DRPM_ERR_OK;
    char *filename = NULL;
    uint32_t filename_len;
    const char *fname;
    uint32_t magic;
    char *name = NULL;
    char *evr = NULL;
    uint16_t patches_count;
    uint32_t files_count;
    uint8_t num;
    uint8_t num2;
    unsigned char buf[4];
    uint8_t read_bytes;

    if (!skip_magic) {
        if ((error = rpml_get_uint32(filedesc, &magic)) != DRPM_ERR_OK)
            return error;
        if (magic != MAGIC_RPML)
            return DRPM_ERR_FORMAT;
    }

    if ((error = rpml_get_string(filedesc, &name)) != DRPM_ERR_OK ||
        (error = rpml_get_string(filedesc, &evr)) != DRPM_ERR_OK)
        goto cleanup;

    if ((patch->nevr = malloc(strlen(name) + strlen(evr) + 2)) == NULL) {
        error = DRPM_ERR_FORMAT;
        goto cleanup;
    }

    sprintf(patch->nevr, "%s-%s", name, evr);

    if ((error = rpml_get_string(filedesc, NULL)) != DRPM_ERR_OK || // build host
        (error = rpml_get_uint32(filedesc, NULL)) != DRPM_ERR_OK || // build time
        (error = rpml_get_uint16(filedesc, &patches_count)) != DRPM_ERR_OK)
        goto cleanup;

    if (patches_count > 0) {
        for (uint16_t i = 0; i < patches_count; i++)
            if ((error = rpml_get_string(filedesc, NULL)) != DRPM_ERR_OK)
                goto cleanup;

        if ((error = rpml_get_uint32(filedesc, &files_count)) != DRPM_ERR_OK)
            goto cleanup;

        for (uint32_t i = 0; i < files_count; i++) {
            if (!resize16((void **)&patch->files, patch->file_count, sizeof(struct patch_file))) {
                error = DRPM_ERR_MEMORY;
                goto cleanup;
            }
            if ((error = rpml_get_filename(filedesc, &filename, &filename_len)))
                goto cleanup;
            if ((patch->files[patch->file_count].name = malloc(strlen(filename) + 1)) == NULL) {
                error = DRPM_ERR_MEMORY;
            }
            strcpy(patch->files[patch->file_count].name, filename);
            patch->files[patch->file_count].mode = S_IFREG;
            patch->files[patch->file_count].flags = RPMFILE_UNPATCHED;
            memset(patch->files[patch->file_count].md5, 0, MD5_DIGEST_LENGTH);
            patch->file_count++;
        }
    }

    while (true) {
        if ((error = rpml_get_filename(filedesc, &filename, &filename_len)) != DRPM_ERR_OK)
            goto cleanup;

        if (strlen(filename) == 0)
            break;

        if (!resize16((void **)&patch->files, patch->file_count, sizeof(struct patch_file))) {
            error = DRPM_ERR_MEMORY;
            goto cleanup;
        }

        fname = (strncmp(filename, "./", 2) == 0) ? filename + 2 : filename;

        if ((patch->files[patch->file_count].name = malloc(strlen(fname) + 1)) == NULL) {
            error = DRPM_ERR_MEMORY;
            goto cleanup;
        }

        patch->files[patch->file_count].flags = RPMFILE_NONE;
        memset(patch->files[patch->file_count].md5, 0, MD5_DIGEST_LENGTH);

        if ((error = rpml_get_uint16(filedesc, &patch->files[patch->file_count].mode)) != DRPM_ERR_OK)
            goto cleanup;

        if (patch->files[patch->file_count].mode != 0) {
            if (read(filedesc, &num, 1) != 1) {
                error = DRPM_ERR_FORMAT;
                goto cleanup;
            }

            if (num == 0xFF) {
                if (read(filedesc, &num2, 1) != 1 ||
                    read(filedesc, &num, 1) != 1) {
                    error = DRPM_ERR_FORMAT;
                    goto cleanup;
                }
                if (((num2 > 0) && (error = rpml_skip(filedesc, num2 + 1)) != DRPM_ERR_OK) ||
                    ((num & 0xFC) && (error = rpml_skip(filedesc, (num >> 2 & 0x3F) + 1)) != DRPM_ERR_OK))
                    goto cleanup;
            } else {
                if (((num & 0xE0) && (error = rpml_skip(filedesc, (num >> 5 & 7) + 1)) != DRPM_ERR_OK) ||
                    ((num & 0x1C) && (error = rpml_skip(filedesc, (num >> 2 & 7) + 1)) != DRPM_ERR_OK))
                    goto cleanup;
            }

            if ((S_ISCHR(patch->files[patch->file_count].mode) || S_ISBLK(patch->files[patch->file_count].mode)) &&
                (error = rpml_get_uint32(filedesc, NULL)) != DRPM_ERR_OK) // rdev
                goto cleanup;

            if (S_ISREG(patch->files[patch->file_count].mode) || S_ISLNK(patch->files[patch->file_count].mode)) {
                read_bytes = (num % 4) + 1;
                memset(buf, 0, 4);
                if (read(filedesc, buf + (4 - read_bytes), read_bytes) != read_bytes &&
                    parse_be32(buf) > 0 &&
                    read(filedesc, patch->files[patch->file_count].md5, MD5_DIGEST_LENGTH) != MD5_DIGEST_LENGTH) {
                    error = DRPM_ERR_FORMAT;
                    goto cleanup;
                }
            }
        }

        patch->file_count++;
    }

cleanup:
    free(filename);
    free(name);
    free(evr);

    return error;
}

int patches_read(const char *oldrpmprint, const char *oldpatchrpm, struct rpm_patches **patches)
{
    int error = DRPM_ERR_OK;
    int filedesc;
    struct patch_info *rpmprint;
    struct patch_info *patchrpm;
    uint32_t magic;
    struct rpm *rpmst = NULL;
    struct file_info *files;
    size_t file_count;
    char *fname;

    if (patches == NULL)
        return DRPM_ERR_PROG;

    /* no patching */
    if (oldrpmprint == NULL || oldpatchrpm == NULL) {
        *patches = NULL;
        return DRPM_ERR_OK;
    }

    if ((*patches = malloc(sizeof(struct rpm_patches))) == NULL)
        return DRPM_ERR_MEMORY;

    rpmprint = &(*patches)->rpmprint;
    patchrpm = &(*patches)->patchrpm;

    if ((filedesc = open(oldpatchrpm, O_RDONLY)) < 0) {
        error = DRPM_ERR_IO;
        goto cleanup_fail;
    }

    if ((error = read_rpmlist(filedesc, patchrpm, false)) != DRPM_ERR_OK)
        goto cleanup_fail;

    close(filedesc);

    if ((filedesc = open(oldrpmprint, O_RDONLY)) < 0) {
        error = DRPM_ERR_IO;
        goto cleanup_fail;
    }

    if ((error = read_be32(filedesc, &magic)) != DRPM_ERR_OK)
        goto cleanup_fail;

    switch (magic) {
    case MAGIC_RPM:
        if ((error = rpm_read(&rpmst, oldrpmprint, RPM_ARCHIVE_DONT_READ, NULL, NULL, NULL)) != DRPM_ERR_OK ||
            (error = rpm_get_nevr(rpmst, &rpmprint->nevr)) != DRPM_ERR_OK ||
            (error = rpm_get_file_info(rpmst, &files, &file_count, NULL)) != DRPM_ERR_OK)
            goto cleanup_fail;
        if ((rpmprint->files = malloc(file_count)) == NULL) {
            error = DRPM_ERR_MEMORY;
            goto cleanup_fail;
        }
        rpmprint->file_count = file_count;
        for (size_t i = 0; i < file_count; i++) {
            fname = files[i].name;
            if (fname[0] == '/')
                fname++;
            if ((rpmprint->files[i].name = malloc(strlen(fname) + 1)) == NULL) {
                error = DRPM_ERR_MEMORY;
                goto cleanup_fail;
            }
            strcpy(rpmprint->files[i].name, fname);
            rpmprint->files[i].mode = files[i].mode;
            rpmprint->files[i].flags = files[i].flags;
            if (!parse_md5(rpmprint->files[i].md5, files[i].md5)) {
                error = DRPM_ERR_FORMAT;
                goto cleanup_fail;
            }
        }
        break;
    case MAGIC_RPML:
        if ((error = read_rpmlist(filedesc, rpmprint, true)) != DRPM_ERR_OK)
            goto cleanup_fail;
        break;
    default:
        error = DRPM_ERR_FORMAT;
        goto cleanup_fail;
    }

    goto cleanup;

cleanup_fail:
    patches_destroy(patches);

cleanup:
    close(filedesc);

    return error;
}

int patches_destroy(struct rpm_patches **patches)
{
    if (patches == NULL || *patches == NULL)
        return DRPM_ERR_PROG;

    for (size_t i = 0; i < (*patches)->rpmprint.file_count; i++)
        free((*patches)->rpmprint.files[i].name);
    free((*patches)->rpmprint.files);
    free((*patches)->rpmprint.nevr);

    for (size_t i = 0; i < (*patches)->patchrpm.file_count; i++)
        free((*patches)->patchrpm.files[i].name);
    free((*patches)->patchrpm.files);
    free((*patches)->patchrpm.nevr);

    free(*patches);

    *patches = NULL;

    return DRPM_ERR_OK;
}

int patches_check_nevr(const struct rpm_patches *patches, const char *nevr)
{
    if (patches == NULL)
        return DRPM_ERR_PROG;

    return (strcmp(patches->rpmprint.nevr, nevr) == 0 &&
            strcmp(patches->patchrpm.nevr, nevr) == 0) ?
           DRPM_ERR_OK :
           DRPM_ERR_ARGS;
}

bool is_unpatched(const struct rpm_patches *patches, const char *name,
                  const char rpm_md5[MD5_DIGEST_LENGTH * 2 + 1])
{
    size_t i;
    char patch_md5[MD5_DIGEST_LENGTH * 2 + 1];

    for (i = 0; i < patches->rpmprint.file_count; i++)
        if (strcmp(name, patches->rpmprint.files[i].name) == 0)
            break;

    if (i == patches->rpmprint.file_count ||
        !(patches->rpmprint.files[i].flags & RPMFILE_UNPATCHED))
        return false;

    for (i = 0; i < patches->patchrpm.file_count; i++)
        if (strcmp(name, patches->patchrpm.files[i].name) == 0)
            break;

    if (i == patches->patchrpm.file_count) // shouldn't happen
        return true;

    dump_hex(patch_md5, patches->patchrpm.files[i].md5, MD5_DIGEST_LENGTH);

    return (strcmp(rpm_md5, patch_md5) != 0);
}

/* In the case of an rpm-only identity deltarpm, since identity deltarpms
 * only read one RPM file and rpm-only deltarpms take the RPMs' CPIO
 * archives "as is" (i.e. they are not altered based on filesystem data),
 * there is nothing to diff. */
int fill_nodiff_deltarpm(struct deltarpm *delta, const char *rpm_filename,
                         bool comp_not_set)
{
    struct rpm *solo_rpm;
    char *nevr = NULL;
    int error = DRPM_ERR_OK;

    if (comp_not_set) {
        delta->comp = DRPM_COMP_GZIP;
        delta->comp_level = DRPM_COMP_LEVEL_DEFAULT;
    }

    delta->tgt_comp = DRPM_COMP_NONE;

    if ((delta->sequence = malloc(MD5_DIGEST_LENGTH)) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup;
    }
    delta->sequence_len = MD5_DIGEST_LENGTH;

    if ((error = rpm_read(&solo_rpm, rpm_filename, RPM_ARCHIVE_READ_UNCOMP,
                          NULL, delta->sequence, delta->tgt_md5)) != DRPM_ERR_OK ||
        (error = rpm_fetch_lead_and_signature(solo_rpm, &delta->tgt_lead, &delta->tgt_lead_len)) != DRPM_ERR_OK ||
        (error = rpm_get_nevr(solo_rpm, &nevr)) != DRPM_ERR_OK)
        goto cleanup;

    if ((delta->src_nevr = malloc(strlen(nevr) + 1)) == NULL ||
        (delta->head.tgt_nevr = malloc(strlen(nevr) + 1)) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup;
    }

    strcpy(delta->src_nevr, nevr);
    strcpy(delta->head.tgt_nevr, nevr);

    delta->tgt_size = rpm_size_full(solo_rpm);
    delta->tgt_header_len = rpm_size_header(solo_rpm);

cleanup:
    free(nevr);
    rpm_destroy(&solo_rpm);

    return error;
}

void free_deltarpm(struct deltarpm *delta)
{
    struct deltarpm delta_init = {0};

    if (delta->type == DRPM_TYPE_RPMONLY)
        free(delta->head.tgt_nevr);

    free(delta->src_nevr);
    free(delta->sequence);
    free(delta->tgt_comp_param);
    free(delta->offadjs);
    free(delta->tgt_lead);
    free(delta->int_copies);
    free(delta->ext_copies);
    free(delta->add_data);

    if (delta->int_data_as_ptrs)
        free(delta->int_data.ptrs);
    else
        free(delta->int_data.bytes);

    *delta = delta_init;
}
