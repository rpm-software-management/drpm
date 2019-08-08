/*
    Authors:
        Matej Chalk <mchalk@redhat.com>

    Copyright (C) 2004,2005 Michael Schroeder (mls@suse.de)
    Copyright (C) 2016 Red Hat

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
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#define BUFFER_SIZE 4096

struct checksum {
    unsigned short digest_algo;
    union {
        MD5_CTX md5;
        SHA256_CTX sha256;
    } ctx;
};

static int check_filesize(const char *, unsigned short, const unsigned char *, size_t);
static int check_full(const char *, unsigned short, const unsigned char *, size_t);
static int check_prelink(const char *, unsigned short, const unsigned char *, size_t);
static size_t checksum_digest_len(struct checksum);
static int checksum_final(struct checksum *, unsigned char *);
static int checksum_init(struct checksum *, unsigned short);
static int checksum_update(struct checksum *, const void *, size_t);
static uint16_t elf16(const unsigned char *, bool);
static uint32_t elf32(const unsigned char *, bool);
static uint64_t elf64(const unsigned char *, bool, bool);

/* Expands the compressed sequence of the file order.
 * May perform checks on the individual files.
 * May create an index of CPIO entry lengths and offsets into
 * <*seqfiles_ret> and <*seqfile_len_ret>. */
int expand_sequence(struct cpio_file **seqfiles_ret, size_t *seqfiles_len_ret,
                    const unsigned char *sequence, uint32_t sequence_len,
                    const struct file_info *files, size_t file_count,
                    unsigned short digest_algo, int check_mode)
{
    int error = DRPM_ERR_OK;
    const bool want_seq = (seqfiles_ret != NULL && seqfiles_len_ret != NULL);
    struct cpio_file *seqfiles = NULL;
    size_t *positions;
    size_t positions_len = 0;
    MD5_CTX seq_md5;
    unsigned char seq_md5_digest[MD5_DIGEST_LENGTH];
    unsigned char digest[MAX(MD5_DIGEST_LENGTH, SHA256_DIGEST_LENGTH)];
    bool even = true;
    bool jump = false;
    bool toggle = true;
    unsigned shift = 0;
    size_t number = 0;
    size_t num = 0;
    size_t num_buf = 0;
    size_t pos = 0;
    uint32_t filesize;
    uint16_t rdev;
    char *filename;
    size_t header_len;
    size_t off = 0;
    int (*check)(const char *, unsigned short, const unsigned char *, size_t);

    if (sequence == NULL || sequence_len < MD5_DIGEST_LENGTH)
        return DRPM_ERR_PROG;

    switch (check_mode) {
    case DRPM_CHECK_NONE:
        check = NULL;
        break;
    case DRPM_CHECK_FULL:
        check = check_full;
        break;
    case DRPM_CHECK_FILESIZES:
        check = check_filesize;
        break;
    default:
        return DRPM_ERR_PROG;
    }

    if ((positions = malloc(file_count * sizeof(size_t))) == NULL)
        return DRPM_ERR_MEMORY;

    /* decompressing the file order */
    for (uint32_t i = MD5_DIGEST_LENGTH; i < sequence_len; ) {
        if (even) {
            num_buf = sequence[i] >> 4;
        } else {
            num_buf = sequence[i] & 0x0F;
            i++;
        }
        even = !even;
        if ((num_buf & (1 << 3)) != 0) {
            num_buf ^= 1 << 3;
            if (shift)
                num_buf <<= shift;
            num |= num_buf;
            shift += 3;
            continue;
        }
        if (shift)
            num_buf <<= shift;
        number = num | num_buf;
        num = 0;
        shift = 0;

        if (jump) {
            pos = number;
            toggle = true;
            jump = false;
            continue;
        }
        if (number == 0) {
            jump = true;
            continue;
        }
        if (!toggle) {
            pos += number;
            toggle = true;
            continue;
        }

        while (number-- > 0) {
            if (positions_len > file_count || pos > file_count) {
                error = DRPM_ERR_FORMAT;
                goto cleanup_fail;
            }
            positions[positions_len++] = pos++;
        }

        toggle = false;
    }
    if (shift) {
        error = DRPM_ERR_FORMAT;
        goto cleanup_fail;
    }

    if (want_seq && (seqfiles = malloc((positions_len + 1) * sizeof(struct cpio_file))) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup_fail;
    }

    if (MD5_Init(&seq_md5) != 1) {
        error = DRPM_ERR_OTHER;
        goto cleanup_fail;
    }

    /* constructing an MD5 to match against the DeltaRPM sequence
     * checking that files have not changed,
     * and constructing an index of CPIO entries. */
    for (size_t i, pos = 0; pos < positions_len; pos++) {
        i = positions[pos];

        if (S_ISREG(files[i].mode))
            filesize = files[i].size;
        else if (S_ISLNK(files[i].mode))
            filesize = strlen(files[i].linkto);
        else
            filesize = 0;

        if (S_ISBLK(files[i].mode) || S_ISCHR(files[i].mode))
            rdev = files[i].rdev;
        else
            rdev = 0;

        filename = files[i].name;
        if (filename[0] == '/')
            filename++;

        if (MD5_Update(&seq_md5, filename, strlen(filename) + 1) != 1 ||
            md5_update_be32(&seq_md5, files[i].mode) != 1 ||
            md5_update_be32(&seq_md5, filesize) != 1 ||
            md5_update_be32(&seq_md5, rdev) != 1) {
            error = DRPM_ERR_OTHER;
            goto cleanup_fail;
        }

        if (S_ISLNK(files[i].mode)) {
            if (MD5_Update(&seq_md5, files[i].linkto, strlen(files[i].linkto) + 1) != 1) {
                error = DRPM_ERR_OTHER;
                goto cleanup_fail;
            }
        } else if (S_ISREG(files[i].mode) && filesize > 0) {
            switch (digest_algo) {
            case DIGESTALGO_MD5:
                if (!parse_md5(digest, files[i].md5)) {
                    error = DRPM_ERR_FORMAT;
                    goto cleanup_fail;
                }
                if (MD5_Update(&seq_md5, digest, MD5_DIGEST_LENGTH) != 1) {
                    error = DRPM_ERR_OTHER;
                    goto cleanup_fail;
                }
                break;
            case DIGESTALGO_SHA256:
                if (!parse_sha256(digest, files[i].md5)) {
                    error = DRPM_ERR_FORMAT;
                    goto cleanup_fail;
                }
                if (MD5_Update(&seq_md5, digest, SHA256_DIGEST_LENGTH) != 1) {
                    error = DRPM_ERR_OTHER;
                    goto cleanup_fail;
                }
                break;
            }
            if (check != NULL && (error = check(files[i].name, digest_algo, digest, filesize)) != DRPM_ERR_OK)
                goto cleanup;
        }

        if (want_seq) {
            seqfiles[pos].index = i;

            header_len = CPIO_HEADER_SIZE + strlen(filename) + 3; // "./" prefix
            seqfiles[pos].header_len = header_len + CPIO_PADDING(header_len);

            seqfiles[pos].content_len = filesize + CPIO_PADDING(filesize);

            seqfiles[pos].offset = off;
            off += seqfiles[pos].header_len + seqfiles[pos].content_len;
        }
    }

    if (MD5_Final(seq_md5_digest, &seq_md5) != 1) {
        error = DRPM_ERR_OTHER;
        goto cleanup_fail;
    }

    if (memcmp(sequence, seq_md5_digest, MD5_DIGEST_LENGTH) != 0) {
        error = DRPM_ERR_MISMATCH;
        goto cleanup_fail;
    }

    if (want_seq) {
        seqfiles[positions_len].index = -1;

        header_len = CPIO_HEADER_SIZE + strlen(CPIO_TRAILER) + 1;
        seqfiles[positions_len].header_len = header_len + CPIO_PADDING(header_len);

        seqfiles[positions_len].content_len = 0;

        seqfiles[positions_len].offset = off;

        *seqfiles_ret = seqfiles;
        *seqfiles_len_ret = positions_len + 1;
    }

    goto cleanup;

cleanup_fail:
    free(seqfiles);

cleanup:
    free(positions);

    return error;
}

/******************************* check ********************************/

int check_filesize(const char *filename, unsigned short digest_algo,
                   const unsigned char *digest, size_t filesize)
{
    int error;
    int filedesc;
    unsigned char buf[128];
    ssize_t read_len;
    struct stat stats;
    bool prelink;

    if (stat(filename, &stats) != 0)
        return DRPM_ERR_NOINSTALL;

    if (stats.st_size == (off_t)filesize)
        return DRPM_ERR_OK;

    if (stats.st_size > (off_t)filesize) {
        if ((filedesc = open(filename, O_RDONLY)) < 0)
            return DRPM_ERR_IO;
        if ((read_len = read(filedesc, buf, 128)) > 0) {
            if ((error = is_prelinked(&prelink, filedesc, buf, read_len)) != DRPM_ERR_OK)
                return error;
            if (prelink) {
                close(filedesc);
                return check_prelink(filename, digest_algo, digest, filesize);
            }
        }
        if (read_len < 0) {
            close(filedesc);
            return DRPM_ERR_IO;
        }
        close(filedesc);
    }

    return DRPM_ERR_MISMATCH;
}

int check_full(const char *filename, unsigned short digest_algo,
               const unsigned char *digest, size_t filesize)
{
    int error = DRPM_ERR_OK;
    int filedesc;
    unsigned char buf[BUFFER_SIZE];
    struct checksum chsm;
    unsigned char chsm_digest[MAX(MD5_DIGEST_LENGTH, SHA256_DIGEST_LENGTH)];
    ssize_t read_len;
    struct stat stats;
    bool prelink;

    if ((filedesc = open(filename, O_RDONLY)) < 0)
        return DRPM_ERR_IO;

    if (fstat(filedesc, &stats) != 0) {
        error = DRPM_ERR_NOINSTALL;
        goto cleanup;
    }

    if ((error = checksum_init(&chsm, digest_algo)) != DRPM_ERR_OK)
        goto cleanup;

    if (stats.st_size > (off_t)filesize) {
        if ((read_len = read(filedesc, buf, BUFFER_SIZE)) > 0) {
            if ((error = is_prelinked(&prelink, filedesc, buf, read_len)) != DRPM_ERR_OK)
                return error;
            if (prelink) {
                close(filedesc);
                return check_prelink(filename, digest_algo, digest, filesize);
            }
            if (read_len > (ssize_t)filesize)
                read_len = filesize;
            if ((error = checksum_update(&chsm, buf, read_len)) != DRPM_ERR_OK)
                goto cleanup;
            filesize -= read_len;
        }
    }

    while (filesize > 0 && (read_len = read(filedesc, buf, BUFFER_SIZE)) > 0) {
        if ((size_t)read_len > filesize)
            read_len = filesize;
        if ((error = checksum_update(&chsm, buf, read_len)) != DRPM_ERR_OK)
            goto cleanup;
        filesize -= read_len;
    }

    if ((error = checksum_final(&chsm, chsm_digest)) != DRPM_ERR_OK)
        goto cleanup;

    if (memcmp(chsm_digest, digest, checksum_digest_len(chsm)) != 0) {
        error = DRPM_ERR_MISMATCH;
        goto cleanup;
    }

cleanup:
    close(filedesc);

    return error;
}

int check_prelink(const char *filename, unsigned short digest_algo,
                    const unsigned char *digest, size_t filesize)
{
    int error = DRPM_ERR_OK;
    int filedesc;
    unsigned char buf[BUFFER_SIZE];
    struct checksum chsm;
    unsigned char chsm_digest[MAX(MD5_DIGEST_LENGTH, SHA256_DIGEST_LENGTH)];
    ssize_t read_len;

    if ((error = prelink_open(filename, &filedesc)) != DRPM_ERR_OK)
        return error;

    if ((error = checksum_init(&chsm, digest_algo)) != DRPM_ERR_OK)
        goto cleanup;

    while (filesize > 0 && (read_len = read(filedesc, buf, BUFFER_SIZE)) > 0) {
        if ((size_t)read_len > filesize)
            read_len = filesize;
        if ((error = checksum_update(&chsm, buf, read_len)) != DRPM_ERR_OK)
            goto cleanup;
        filesize -= read_len;
    }

    if (read_len < 0) {
        error = DRPM_ERR_IO;
        goto cleanup;
    }

    if ((error = checksum_final(&chsm, chsm_digest)) != DRPM_ERR_OK)
        goto cleanup;

    if (memcmp(chsm_digest, digest, checksum_digest_len(chsm)) != 0) {
        error = DRPM_ERR_MISMATCH;
        goto cleanup;
    }

cleanup:
    close(filedesc);

    return error;
}

/***************************** MD5/SHA256 *****************************/

int checksum_init(struct checksum *chsm, unsigned short digest_algo)
{
    if (chsm == NULL)
        return DRPM_ERR_PROG;

    switch (digest_algo) {
    case DIGESTALGO_MD5:
        if (MD5_Init(&chsm->ctx.md5) != 1)
            return DRPM_ERR_OTHER;
        break;
    case DIGESTALGO_SHA256:
        if (SHA256_Init(&chsm->ctx.sha256) != 1)
            return DRPM_ERR_OTHER;
        break;
    default:
        return DRPM_ERR_PROG;
    }

    chsm->digest_algo = digest_algo;

    return DRPM_ERR_OK;
}

int checksum_update(struct checksum *chsm, const void *buf, size_t len)
{
    if (chsm == NULL || buf == NULL)
        return DRPM_ERR_PROG;

    switch (chsm->digest_algo) {
    case DIGESTALGO_MD5:
        return MD5_Update(&chsm->ctx.md5, buf, len) != 1 ? DRPM_ERR_OTHER : DRPM_ERR_OK;
    case DIGESTALGO_SHA256:
        return SHA256_Update(&chsm->ctx.sha256, buf, len) != 1 ? DRPM_ERR_OTHER : DRPM_ERR_OK;
    default:
        return DRPM_ERR_PROG;
    }
}

int checksum_final(struct checksum *chsm, unsigned char *digest)
{
    if (chsm == NULL || digest == NULL)
        return DRPM_ERR_PROG;

    switch (chsm->digest_algo) {
    case DIGESTALGO_MD5:
        return MD5_Final(digest, &chsm->ctx.md5) != 1 ? DRPM_ERR_OTHER : DRPM_ERR_OK;
    case DIGESTALGO_SHA256:
        return SHA256_Final(digest, &chsm->ctx.sha256) != 1 ? DRPM_ERR_OTHER : DRPM_ERR_OK;
    default:
        return DRPM_ERR_PROG;
    }
}

size_t checksum_digest_len(struct checksum chsm)
{
    return chsm.digest_algo == DIGESTALGO_MD5 ? MD5_DIGEST_LENGTH : SHA256_DIGEST_LENGTH;
}

/****************************** prelink *******************************/

uint16_t elf16(const unsigned char *buf, bool little_endian)
{
    if (little_endian)
        return buf[0] | buf[1] << 8;
    return parse_be16(buf);
}

uint32_t elf32(const unsigned char *buf, bool little_endian)
{
    if (little_endian)
        return buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24;
    return parse_be32(buf);
}

uint64_t elf64(const unsigned char *buf, bool little_endian, bool is64)
{
    if (is64) {
        buf += little_endian ? 4 : 0;
        if (buf[0] > 0 || buf[1] > 0 || buf[2] > 0 || buf[3] > 0)
            return UINT64_MAX;
        buf += little_endian ? -4 : 4;
    }

    if (little_endian)
        return buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24;
    return parse_be32(buf);
}

int is_prelinked(bool *is_prelinked_ret, int fd, const unsigned char *buf, ssize_t read_len)
{
    int error = DRPM_ERR_OK;
    bool is_prelinked = true;
    size_t len = read_len;
    bool le;
    bool is64;
    off_t soff;
    int snum;
    int ssiz;
    int i;
    int stridx;
    unsigned char *sects = NULL;
    unsigned char *strsect = NULL;
    unsigned slen;
    unsigned o;

    if (is_prelinked_ret == NULL || buf == NULL)
        return DRPM_ERR_PROG;

    if (read_len < 0)
        return DRPM_ERR_IO;

    if (len < 0x34 ||
        buf[0] != 0x7F || buf[1] != 'E' || buf[2] != 'L' || buf[3] != 'F') {
        is_prelinked = false;
        goto cleanup;
    }

    is64 = (buf[4] == 2);
    le = (buf[5] != 2);

    if (is64 && len < 0x40) {
        is_prelinked = false;
        goto cleanup;
    }

    soff = elf64(is64 ? buf + 40 : buf + 32, le, is64);
    if (soff == (off_t)~0) {
        is_prelinked = false;
        goto cleanup;
    }

    ssiz = elf16(buf + (is64 ? 0x40 - 6 : 0x34 - 6), le);
    if (ssiz < (is64 ? 64 : 40) || ssiz >= 32768) {
        is_prelinked = false;
        goto cleanup;
    }

    snum = elf16(buf + (is64 ? 0x40 - 4 : 0x34 - 4), le);
    stridx = elf16(buf + (is64 ? 0x40 - 2 : 0x34 - 2), le);
    if (stridx >= snum) {
        is_prelinked = false;
        goto cleanup;
    }

    if ((sects = malloc(snum * ssiz)) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup;
    }

    if (pread(fd, sects, snum * ssiz, soff) != snum * ssiz) {
        is_prelinked = false;
        goto cleanup;
    }

    strsect = sects + stridx * ssiz;
    if (elf32(strsect + 4, le) != 3) {
        is_prelinked = false;
        goto cleanup;
    }

    soff = elf64(is64 ? strsect + 24 : strsect + 16, le, is64);
    slen = elf64(is64 ? strsect + 32 : strsect + 20, le, is64);
    if (soff == (off_t)~0 || slen == (unsigned)~0 || (int)slen < 0) {
        is_prelinked = false;
        goto cleanup;
    }

    if ((strsect = malloc(slen)) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup;
    }

    if (pread(fd, strsect, slen, soff) != (ssize_t)slen) {
        is_prelinked = false;
        goto cleanup;
    }

    for (i = 0; i < snum; i++) {
        o = elf32(sects + i * ssiz, le);
        if (o > slen)
            continue;
        if (o + 18 <= slen && memcmp(strsect + o, ".gnu.prelink_undo", 18) == 0)
            break;
    }
    is_prelinked = (i != snum);

cleanup:
    free(strsect);
    free(sects);

    *is_prelinked_ret = is_prelinked;

    return error;
}

int prelink_open(const char *filename, int *filedesc)
{
    pid_t pid;
    int fd;
    int status;
    struct stat stats;
    char template[] = "/tmp/drpm.XXXXXX";

    if (filename == NULL || filedesc == NULL)
        return DRPM_ERR_PROG;

    if (stat("/usr/sbin/prelink", &stats) != 0)
        return DRPM_ERR_OTHER;

    if ((fd = mkstemp(template)) < 0)
        return DRPM_ERR_IO;
    close(fd);

    pid = fork();
    if (pid == (pid_t)-1) {
        return DRPM_ERR_OTHER;
    }
    if (pid == 0) {
        execl("/usr/sbin/prelink", "prelink", "-o", template, "-u", filename, NULL);
        _exit(1);
    }

    while (waitpid(pid, &status, 0) == (pid_t)-1);

    if ((fd = open(template, O_RDONLY)) < 0)
        return DRPM_ERR_IO;

    unlink(template);

    *filedesc = fd;

    return DRPM_ERR_OK;
}

