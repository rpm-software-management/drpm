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

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <linux/kdev_t.h>

#define MAX_OPEN_FILES 50
#define MAX_CORE_BLOCKS 5000

#define BLOCK_SIZE (1 << 13)

#define BLK_FREE 0
#define BLK_CORE 1
#define BLK_CORE_NOPAGE 2
#define BLK_PAGE 3

#define BLOCKS(size) (1 + ((size) - 1) / BLOCK_SIZE)

/* a list of open files */
struct open_file {
    struct open_file *prev;
    struct open_file *next;
    int filedesc;
    const char *name;
    off_t offset;
};

/* a block */
struct block {
    struct block *next;
    int type;
    unsigned id;
    /* core blocks store the buffer directly, while page blocks
     * only store an offset within a temporary file from which to read
     * the data */
    union {
        off_t offset;
        unsigned char *buffer;
    } data;
};

struct blocks {
    struct block *free_core_blocks;
    struct block *core_blocks;
    size_t core_blocks_count;

    struct block *page_blocks;
    size_t page_blocks_count;
    int page_filedesc;

    struct block **blocks_table;
    size_t *blocks_max;

    unsigned char *cpio_buffer;
    const char *linkto;
    ssize_t cpio_files_index;

    const struct cpio_file *cpio_files;
    size_t cpio_files_len;
    const struct file_info *files;

    bool from_rpm;
    union {
        struct {
            struct open_file *files_head;
            struct open_file *files_tail;
            unsigned short file_count;
            struct open_file **open_files;
        } from_filesytem;
        struct {
            struct rpm *old_rpm;
            unsigned rpm_id;
            uint64_t left;
            unsigned char *old_header;
            size_t old_header_size;
            size_t old_header_offset;
        } from_rpm;
    } rpm_files;

    struct block *last_block;

    int (*fill_block)(struct blocks *, struct block *, size_t, size_t);
};

static int fillblock_filesystem(struct blocks *, struct block *, size_t, size_t);
static int fillblock_prelink(struct blocks *, struct block *, size_t, size_t, const struct cpio_file *);
static int fillblock_rpm_rpmonly(struct blocks *, struct block *, size_t, size_t);
static int fillblock_rpm_standard(struct blocks *, struct block *, size_t, size_t);
static struct block *get_free_core_block(struct blocks *);
static int get_block(struct blocks *, struct block **, size_t, size_t);
static int new_core_block(struct blocks *, struct block **);
static int push_block(struct blocks *, const struct block *, size_t);
static int read_page_block(struct blocks *, struct block *, const struct block *);
static int write_page_block(struct blocks *, const struct block *, size_t);

/* returns size of block */
size_t block_size()
{
    return BLOCK_SIZE;
}

/* determines block ID from offset */
size_t block_id(uint64_t offset)
{
    return offset / BLOCK_SIZE;
}

/* creates blocks for reading external data */
int blocks_create(struct blocks **blks_ret,
                  uint64_t ext_data_len, const struct file_info *files,
                  const struct cpio_file *cpio_files, size_t cpio_files_len,
                  const uint32_t *ext_copies, size_t ext_copies_count,
                  struct rpm *old_rpm, bool rpm_only)
{
    int error = DRPM_ERR_OK;
    const size_t block_count = BLOCKS(ext_data_len);
    uint64_t off = 0;
    size_t max_cpio_header_len;
    uint32_t old_header_size;
    struct blocks blks = {
        .page_filedesc = -1,
        .cpio_files_index = -1,
        .cpio_files = cpio_files,
        .cpio_files_len = cpio_files_len,
        .files = files,
        .from_rpm = (old_rpm != NULL)
    };

    if (blks_ret == NULL)
        return DRPM_ERR_PROG;

    if (block_count >= UINT32_MAX)
        return DRPM_ERR_OVERFLOW;

    if (blks.from_rpm) {
        blks.rpm_files.from_rpm.old_rpm = old_rpm;
        blks.rpm_files.from_rpm.rpm_id = 0;
        if (rpm_only) {
            blks.rpm_files.from_rpm.left = ext_data_len;
            if ((error = rpm_fetch_header(old_rpm, &blks.rpm_files.from_rpm.old_header, &old_header_size)) != DRPM_ERR_OK)
                goto cleanup;
            blks.rpm_files.from_rpm.old_header_size = old_header_size;
            blks.rpm_files.from_rpm.old_header_offset = 0;
            blks.fill_block = fillblock_rpm_rpmonly;
        } else {
            blks.rpm_files.from_rpm.left = 0;
            blks.rpm_files.from_rpm.old_header = NULL;
            blks.rpm_files.from_rpm.old_header_size = 0;
            blks.rpm_files.from_rpm.old_header_offset = 0;
            blks.fill_block = fillblock_rpm_standard;
        }
    } else {
        if ((blks.rpm_files.from_filesytem.open_files = calloc(cpio_files_len, sizeof(struct open_file *))) == NULL) {
            error = DRPM_ERR_MEMORY;
            goto cleanup;
        }
        blks.rpm_files.from_filesytem.files_head = NULL;
        blks.rpm_files.from_filesytem.files_tail = NULL;
        blks.rpm_files.from_filesytem.file_count = 0;
        blks.fill_block = fillblock_filesystem;
    }

    if ((*blks_ret = malloc(sizeof(struct blocks))) == NULL ||
        (blks.blocks_table = calloc(block_count, sizeof(struct block *))) == NULL ||
        (blks.blocks_max = calloc(block_count, sizeof(size_t))) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup;
    }

    for (size_t blk_i, blk_l, i = 0; i < ext_copies_count; i++) {
        off += (int32_t)ext_copies[2 * i];
        blk_i = off / BLOCK_SIZE;
        off += ext_copies[2 * i + 1];
        blk_l = BLOCKS(off);
        for ( ; blk_i < blk_l; blk_i++)
            blks.blocks_max[blk_i] = i;
    }

    max_cpio_header_len = CPIO_HEADER_SIZE + strlen(CPIO_TRAILER) + 1;
    max_cpio_header_len += CPIO_PADDING(max_cpio_header_len);
    for (size_t i = 0; i < cpio_files_len; i++)
        if (cpio_files[i].header_len > max_cpio_header_len)
            max_cpio_header_len = cpio_files[i].header_len;

    if ((blks.cpio_buffer = malloc(max_cpio_header_len)) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup;
    }

    **blks_ret = blks;

    return DRPM_ERR_OK;

cleanup:
    free(*blks_ret);
    free(blks.blocks_table);
    free(blks.blocks_max);
    free(blks.cpio_buffer);

    return error;
}

/* frees block data */
int blocks_destroy(struct blocks **blks_ref)
{
    struct blocks *blks;
    struct block *blk_lists[3];

    if (blks_ref == NULL || *blks_ref == NULL)
        return DRPM_ERR_PROG;

    blks = *blks_ref;

    if (blks->from_rpm) {
        free(blks->rpm_files.from_rpm.old_header);
    } else {
        for (struct open_file *tmp, *file = blks->rpm_files.from_filesytem.files_head; file != NULL; ) {
            close(file->filedesc);
            tmp = file;
            file = file->next;
            free(tmp);
        }
        free(blks->rpm_files.from_filesytem.open_files);
    }

    blk_lists[0] = blks->core_blocks;
    blk_lists[1] = blks->free_core_blocks;
    blk_lists[2] = blks->page_blocks;

    for (unsigned short i = 0; i < 3; i++) {
        for (struct block *blk = blk_lists[i], *tmp; blk != NULL; ) {
            if (blk->type != BLK_PAGE)
                free(blk->data.buffer);
            tmp = blk;
            blk = blk->next;
            free(tmp);
        }
    }

    if (!(blks->page_filedesc < 0))
        close(blks->page_filedesc);

    free(blks->blocks_table);
    free(blks->blocks_max);
    free(blks->cpio_buffer);

    free(*blks_ref);

    *blks_ref = NULL;

    return DRPM_ERR_OK;
}

/* fetches external data */
int blocks_next(struct blocks *blks, unsigned char buffer[BLOCK_SIZE], size_t *buffer_len,
                uint64_t offset, size_t copy_len, size_t copy_cnt, size_t id)
{
    int error;
    size_t blk_off;

    if (blks == NULL || buffer == NULL || buffer_len == NULL)
        return DRPM_ERR_PROG;

    if (blks->last_block == NULL || id != blks->last_block->id) {
        blks->last_block = blks->blocks_table[id];
        if ((blks->last_block == NULL || blks->last_block->type == BLK_PAGE) &&
            (error = get_block(blks, &blks->last_block, id, copy_cnt)) != DRPM_ERR_OK)
            return error;
    }

    blk_off = offset % BLOCK_SIZE;

    *buffer_len = (blk_off + copy_len > BLOCK_SIZE) ? BLOCK_SIZE - blk_off : copy_len;
    memcpy(buffer, blks->last_block->data.buffer + blk_off, *buffer_len);

    return DRPM_ERR_OK;
}

/* gets new block and fills it */
int get_block(struct blocks *blks, struct block **blk_ret, size_t id, size_t copy_cnt)
{
    static size_t cleanup_count = 0;
    int error;
    struct block *blk;
    struct block *page_blk;

    if (blks == NULL || blk_ret == NULL)
        return DRPM_ERR_PROG;

    *blk_ret = NULL;

    blk = blks->blocks_table[id];
    if (blk != NULL && (blk->type == BLK_CORE || blk->type == BLK_CORE_NOPAGE)) {
        *blk_ret = blk;
        return DRPM_ERR_OK;
    }

    if ((blk = get_free_core_block(blks)) == NULL) {
        if (blks->core_blocks_count < MAX_CORE_BLOCKS && (++cleanup_count % 8) != 0) {
            if ((error = new_core_block(blks, &blk)) != DRPM_ERR_OK)
                return error;
        } else {
            for (struct block **blk_ptr = &blks->core_blocks; (blk = *blk_ptr) != NULL; blk_ptr = &blk->next) {
                if (blks->blocks_max[blk->id] < copy_cnt ||
                    (blk->id == id && blks->blocks_max[blk->id] == copy_cnt)) {
                    *blk_ptr = blk->next;
                    blks->blocks_table[blk->id] = NULL;
                    blk->type = BLK_FREE;
                    blk->next = blks->free_core_blocks;
                    blks->free_core_blocks = blk;
                } else {
                    blk_ptr = &blk->next;
                }
            }
            if ((blk = get_free_core_block(blks)) == NULL) {
                if (blks->core_blocks_count < MAX_CORE_BLOCKS) {
                    if ((error = new_core_block(blks, &blk)) != DRPM_ERR_OK)
                        return error;
                } else {
                    for (struct block **blk_ptr = &blks->core_blocks; (blk = *blk_ptr) != NULL; blk_ptr = &blk->next) {
                        if (blk->next == NULL) {
                            *blk_ptr = NULL;
                            break;
                        }
                    }
                    blk->next = blks->core_blocks;
                    blks->core_blocks = blk;
                    if (blk->type == BLK_PAGE) {
                        if ((error = write_page_block(blks, blk, copy_cnt)) != DRPM_ERR_OK)
                            return error;
                    } else {
                        blks->blocks_table[blk->id] = NULL;
                    }
                    blk->type = BLK_FREE;
                }
            }
        }
    }

    page_blk = blks->blocks_table[id];
    if (page_blk != NULL && page_blk->type == BLK_PAGE)
        return read_page_block(blks, blk, page_blk);

    /* filling block */
    if ((error = blks->fill_block(blks, blk, id, copy_cnt)) != DRPM_ERR_OK)
        return error;

    *blk_ret = blks->blocks_table[id] = blk;

    return DRPM_ERR_OK;
}

/* allocates a new block */
int new_core_block(struct blocks *blks, struct block **new_ret)
{
    struct block *new;

    if (blks == NULL || new_ret == NULL)
        return DRPM_ERR_PROG;

    if ((new = malloc(sizeof(struct block))) == NULL ||
        (new->data.buffer = malloc(BLOCK_SIZE)) == NULL) {
        free(new);
        return DRPM_ERR_MEMORY;
    }

    new->type = BLK_FREE;
    new->next = blks->core_blocks;
    blks->core_blocks = new;
    blks->core_blocks_count++;

    *new_ret = new;

    return DRPM_ERR_OK;
}

/* pops a free core block and pushes it to core blocks for reuse */
struct block *get_free_core_block(struct blocks *blks)
{
    struct block *blk;

    if (blks->free_core_blocks == NULL)
        return NULL;

    blk = blks->free_core_blocks;
    blks->free_core_blocks = blks->free_core_blocks->next;
    blk->next = blks->core_blocks;
    blks->core_blocks = blk;

    return blk;
}

/* inserts a block in table */
int push_block(struct blocks *blks, const struct block *blk, size_t copy_cnt)
{
    int error;
    struct block *new;

    if (blks == NULL || blk == NULL)
        return DRPM_ERR_PROG;

    if ((new = get_free_core_block(blks)) == NULL) {
        if (blks->core_blocks_count < MAX_CORE_BLOCKS) {
            if ((error = new_core_block(blks, &new)) != DRPM_ERR_OK)
                return error;
        } else if (blk->type == BLK_CORE) {
            return write_page_block(blks, blk, copy_cnt);
        } else {
            blks->blocks_table[blk->id] = NULL;
            return DRPM_ERR_OK;
        }
    }

    new->id = blk->id;
    new->type = blk->type;
    memcpy(new->data.buffer, blk->data.buffer, BLOCK_SIZE);

    blks->blocks_table[new->id] = new;

    return DRPM_ERR_OK;
}

/* insert a page block in table and writes its data to temporary file */
int write_page_block(struct blocks *blks, const struct block *blk, size_t copy_cnt)
{
    struct block *new;
    char template[] = "/tmp/drpmpageXXXXXX";

    if (blks == NULL || blk == NULL || blk->type == BLK_PAGE)
        return DRPM_ERR_PROG;

    for (new = blks->page_blocks; new != NULL; new = new->next) {
        if (new->id == blk->id) {
            blks->blocks_table[new->id] = new;
            return DRPM_ERR_OK;
        }
    }

    for (new = blks->page_blocks; new != NULL; new = new->next)
        if (blks->blocks_max[new->id] < copy_cnt)
            break;

    if (new == NULL) {
        if ((new = malloc(sizeof(struct block))) == NULL)
            return DRPM_ERR_MEMORY;
        new->type = BLK_PAGE;
        new->data.offset = blks->page_blocks_count;
        new->next = blks->page_blocks;
        blks->page_blocks = new;
        blks->page_blocks_count++;
        if (blks->page_filedesc < 0) {
            if ((blks->page_filedesc = mkstemp(template)) < 0) {
                free(new);
                return DRPM_ERR_IO;
            }
            unlink(template);
        }
    }

    new->id = blk->id;

    if (pwrite(blks->page_filedesc, blk->data.buffer, BLOCK_SIZE, new->data.offset * BLOCK_SIZE) != BLOCK_SIZE) {
        free(new);
        return DRPM_ERR_IO;
    }

    blks->blocks_table[new->id] = new;

    return DRPM_ERR_OK;
}

/* reads page block data from temporary file into destination block */
int read_page_block(struct blocks *blks, struct block *dst, const struct block *src)
{
    if (blks == NULL || dst == NULL || src == NULL ||
        blks->page_filedesc < 0 || dst->type == BLK_PAGE || src->type != BLK_PAGE)
        return DRPM_ERR_PROG;

    if (pread(blks->page_filedesc, dst->data.buffer, BLOCK_SIZE, src->data.offset * BLOCK_SIZE) != BLOCK_SIZE)
        return DRPM_ERR_IO;

    dst->id = src->id;
    dst->type = BLK_CORE;
    blks->blocks_table[dst->id] = dst;

    return DRPM_ERR_OK;
}

/* fills CPIO header and linkto buffers based on file info at <index> */
void fill_cpio_header(struct blocks *blks, ssize_t index)
{
    struct cpio_header header = {0};
    struct file_info file;
    char *name;

    if (index < 0) {
        header.nlink = 1;
        header.namesize = strlen(CPIO_TRAILER) + 1;
        cpio_header_write(&header, (char *)blks->cpio_buffer);
        strcpy((char *)blks->cpio_buffer + CPIO_HEADER_SIZE, CPIO_TRAILER);
        memcpy(blks->cpio_buffer + CPIO_HEADER_SIZE + header.namesize,
               "\0\0\0", CPIO_PADDING(CPIO_HEADER_SIZE + header.namesize));
        return;
    }

    file = blks->files[index];
    name = file.name;

    if (name[0] == '/')
        name++;

    if (S_ISREG(file.mode)) {
        header.filesize = file.size;
    } else if (S_ISLNK(file.mode)) {
        header.filesize = strlen(file.linkto);
        blks->linkto = file.linkto;
    }

    if (S_ISBLK(file.mode) || S_ISCHR(file.mode)) {
        header.rdevmajor = MAJOR(file.rdev);
        header.rdevminor = MINOR(file.rdev);
    }

    header.nlink = 1;
    header.mode = file.mode;
    header.namesize = strlen(name) + 3; // "./" prefix

    cpio_header_write(&header, (char *)blks->cpio_buffer);
    strcpy((char *)blks->cpio_buffer + CPIO_HEADER_SIZE, "./");
    strcpy((char *)blks->cpio_buffer + CPIO_HEADER_SIZE + 2, name);
    memcpy(blks->cpio_buffer + CPIO_HEADER_SIZE + header.namesize,
           "\0\0\0", CPIO_PADDING(CPIO_HEADER_SIZE + header.namesize));
}

/* opens new file and appends it to list, sets <prelinked> indicator */
int open_new_file(struct blocks *blks, bool *prelinked, size_t index)
{
    int error;
    struct open_file *new = NULL;
    struct stat stats;
    int filedesc;
    struct file_info file;
    unsigned char plnk_buf[128];
    struct open_file *files_head;
    struct open_file *files_tail;

    if (blks == NULL || prelinked == NULL)
        return DRPM_ERR_PROG;

    file = blks->files[blks->cpio_files[index].index];
    files_head = blks->rpm_files.from_filesytem.files_head;
    files_tail = blks->rpm_files.from_filesytem.files_tail;

    *prelinked = false;

    if ((filedesc = open(file.name, O_RDONLY)) < 0)
        return DRPM_ERR_IO;

    if (fstat(filedesc, &stats) == 0 && stats.st_size != file.size) {
        if ((error = is_prelinked(prelinked, filedesc, plnk_buf, pread(filedesc, plnk_buf, 128, SEEK_SET))) != DRPM_ERR_OK) {
            close(filedesc);
            return error;
        }
        if (*prelinked) {
            close(filedesc);
            return DRPM_ERR_OK;
        }
    }

    if (blks->rpm_files.from_filesytem.file_count < MAX_OPEN_FILES) {
        if ((new = malloc(sizeof(struct open_file))) == NULL) {
            close(filedesc);
            return DRPM_ERR_MEMORY;
        }
        blks->rpm_files.from_filesytem.file_count++;
    } else {
        new = files_head;
        files_head = files_head->next;
        if (files_head == NULL)
            files_tail = NULL;
        else
            files_head->prev = NULL;
        close(new->filedesc);
    }

    new->filedesc = filedesc;
    new->name = file.name;
    new->offset = 0;
    new->prev = NULL;
    new->next = NULL;

    if (files_head == NULL) {
        files_head = files_tail = new;
    } else {
        files_tail->next = new;
        new->prev = files_tail;
        files_tail = new;
    }

    blks->rpm_files.from_filesytem.files_head = files_head;
    blks->rpm_files.from_filesytem.files_tail = files_tail;

    blks->rpm_files.from_filesytem.open_files[index] = new;

    return DRPM_ERR_OK;
}

/* gets open file and moves it to end of list */
struct open_file *get_open_file(struct blocks *blks, size_t index)
{
    struct open_file *file = blks->rpm_files.from_filesytem.open_files[index];
    struct open_file *files_head = blks->rpm_files.from_filesytem.files_head;
    struct open_file *files_tail = blks->rpm_files.from_filesytem.files_tail;

    if (file == NULL)
        return NULL;

    if (file->next == NULL)
        return file;

    file->next->prev = file->prev;

    if (file->prev == NULL)
        files_head = file->next;
    else
        file->prev->next = file->next;

    file->next = NULL;

    file->prev = files_tail;
    files_tail->next = file;
    files_tail = file;

    blks->rpm_files.from_filesytem.files_head = files_head;
    blks->rpm_files.from_filesytem.files_tail = files_tail;

    return file;
}

/***************************** fill block *****************************/

/* Fills a block from old RPM in the case of a standard delta.
 * Uses stored file order to quickly locate files.
 * CPIO entries are altered in the same way as when creating the delta. */
int fillblock_rpm_standard(struct blocks *blks, struct block *blk, size_t id, size_t copy_cnt)
{
    int error = DRPM_ERR_OK;
    const struct cpio_file *cpio;
    size_t len = BLOCK_SIZE;
    size_t off;
    size_t read_len;
    unsigned char *buf_ptr;
    ssize_t i;
    struct cpio_header cpio_hdr;
    char cpio_buf[CPIO_HEADER_SIZE] = {0};
    size_t c_namesize;
    size_t c_filesize;
    char *name;
    char *name_buffer = NULL;
    char *name_buffer_tmp;
    size_t name_buffer_len = 0;
    struct rpm *old_rpm;
    uint64_t left;
    size_t rpm_id;

    if (blks == NULL || blk == NULL)
        return DRPM_ERR_PROG;

    old_rpm = blks->rpm_files.from_rpm.old_rpm;
    left = blks->rpm_files.from_rpm.left;
    rpm_id = blks->rpm_files.from_rpm.rpm_id;

    buf_ptr = blk->data.buffer;

    while (true) {
        if (left > 0) {
            cpio = blks->cpio_files + blks->cpio_files_index;
            if (left > cpio->content_len) {
                off = cpio->header_len + cpio->content_len - left;
                read_len = left - cpio->content_len;
                if (read_len > len)
                    read_len = len;
                memcpy(buf_ptr, blks->cpio_buffer + off, read_len);
                buf_ptr += read_len;
                left -= read_len;
                len -= read_len;
            }
            if (len > 0 && left > 0) {
                read_len = MIN(len, left);
                if (S_ISLNK(blks->files[cpio->index].mode)) {
                    strncpy((char *)buf_ptr, blks->linkto, read_len);
                    blks->linkto += MIN(strlen(blks->linkto), read_len);
                } else if ((error = rpm_archive_read_chunk(old_rpm, buf_ptr, read_len)) != DRPM_ERR_OK) {
                    break;
                }
                buf_ptr += read_len;
                left -= read_len;
                len -= read_len;
            }
        }

        if (len > 0 && blks->cpio_files_index >= 0 &&
            blks->cpio_files[blks->cpio_files_index].index < 0) {
            memset(buf_ptr, 0, len);
            len = 0;
        }

        if (len == 0) {
            blk->type = BLK_CORE;
            blk->id = rpm_id++;

            if (blk->id == id) {
                error = DRPM_ERR_OK;
                break;
            }

            if (blk->id > id) {
                error = DRPM_ERR_PROG;
                break;
            }

            if (blks->blocks_max[blk->id] > copy_cnt &&
                (error = push_block(blks, blk, copy_cnt)) != DRPM_ERR_OK)
                break;

            len = BLOCK_SIZE;
            buf_ptr = blk->data.buffer;
            continue;
        }

        blks->cpio_files_index++;
        cpio = blks->cpio_files + blks->cpio_files_index;
        i = cpio->index;

        if (i < 0) {
            fill_cpio_header(blks, i);
            left = cpio->header_len + cpio->content_len;
            continue;
        }

        while (true) {
            if ((error = rpm_archive_read_chunk(old_rpm, cpio_buf, CPIO_HEADER_SIZE)) != DRPM_ERR_OK ||
                (error = cpio_header_read(&cpio_hdr, cpio_buf)) != DRPM_ERR_OK)
                break;

            c_namesize = cpio_hdr.namesize;
            c_filesize = cpio_hdr.filesize;
            c_filesize += CPIO_PADDING(c_filesize);

            if (c_namesize > name_buffer_len) {
                if ((name_buffer_tmp = realloc(name_buffer, c_namesize)) == NULL) {
                    error = DRPM_ERR_MEMORY;
                    break;
                }
                name_buffer = name_buffer_tmp;
                name_buffer_len = c_namesize;
            }

            if ((error = rpm_archive_read_chunk(old_rpm, name_buffer, c_namesize)) != DRPM_ERR_OK)
                break;

            name = name_buffer;
            name[c_namesize - 1] = '\0';

            if (strcmp(name, CPIO_TRAILER) == 0) {
                error = DRPM_ERR_FORMAT;
                break;
            }

            if (strncmp(name, "./", 2) == 0)
                name += 2;

            if ((error = rpm_archive_read_chunk(old_rpm, NULL, CPIO_PADDING(CPIO_HEADER_SIZE + c_namesize))) != DRPM_ERR_OK)
                break;

            if (strcmp(name, blks->files[i].name +
                             ((blks->files[i].name[0] == '/') ? 1 : 0)) == 0) {
                error = DRPM_ERR_OK;
                break;
            }

            if ((error = rpm_archive_read_chunk(old_rpm, NULL, c_filesize)) != DRPM_ERR_OK)
                break;
        }
        if (error != DRPM_ERR_OK)
            break;

        fill_cpio_header(blks, cpio->index);

        if (!S_ISREG(blks->files[cpio->index].mode)) {
            if ((error = rpm_archive_read_chunk(old_rpm, NULL, c_filesize)) != DRPM_ERR_OK)
                break;
        } else if (c_filesize != cpio->content_len) {
            error = DRPM_ERR_MISMATCH;
            break;
        }

        left = cpio->header_len + cpio->content_len;
    }

    blks->rpm_files.from_rpm.left = left;
    blks->rpm_files.from_rpm.rpm_id = rpm_id;

    free(name_buffer);

    return error;
}

/* Fills a block from old RPM in the case of an rpm-only delta.
 * CPIO data is not altered, but old header is prepended. */
int fillblock_rpm_rpmonly(struct blocks *blks, struct block *blk, size_t id, size_t copy_cnt)
{
    int error;
    size_t read_len;
    size_t header_read_len;
    unsigned char *header;
    size_t header_size;
    size_t header_offset;
    uint64_t left;
    struct rpm *old_rpm;
    size_t rpm_id;

    if (blks == NULL || blk == NULL)
        return DRPM_ERR_PROG;

    header = blks->rpm_files.from_rpm.old_header;
    header_size = blks->rpm_files.from_rpm.old_header_size;
    header_offset = blks->rpm_files.from_rpm.old_header_offset;
    left = blks->rpm_files.from_rpm.left;
    old_rpm = blks->rpm_files.from_rpm.old_rpm;
    rpm_id = blks->rpm_files.from_rpm.rpm_id;

    while (true) {
        read_len = MIN(left, BLOCK_SIZE);

        if (header_offset < header_size) {
            if (header_offset + read_len > header_size) {
                header_read_len = header_size - header_offset;
                if ((error = rpm_archive_read_chunk(old_rpm,
                                                    blk->data.buffer + header_read_len,
                                                    read_len - header_read_len)) != DRPM_ERR_OK)
                    break;
            } else {
                header_read_len = read_len;
            }
            memcpy(blk->data.buffer, header + header_offset, header_read_len);
            header_offset += header_read_len;
        } else {
            if ((error = rpm_archive_read_chunk(old_rpm, blk->data.buffer, read_len)) != DRPM_ERR_OK)
                break;
        }

        left -= read_len;

        if (read_len < BLOCK_SIZE)
            memset(blk->data.buffer + read_len, 0, BLOCK_SIZE - read_len);

        blk->type = BLK_CORE;
        blk->id = rpm_id++;

        if (blk->id == id) {
            error = DRPM_ERR_OK;
            break;
        }

        if (blk->id > id) {
            error = DRPM_ERR_PROG;
            break;
        }

        if (blks->blocks_max[blk->id] > copy_cnt &&
            (error = push_block(blks, blk, copy_cnt)) != DRPM_ERR_OK)
            break;
    }

    blks->rpm_files.from_rpm.old_header_offset = header_offset;
    blks->rpm_files.from_rpm.left = left;
    blks->rpm_files.from_rpm.rpm_id = rpm_id;

    return error;
}

/* Fills block from filesystem data (only works for standard deltas).
 * CPIO entries are created from installed files to match the pattern used
 * in altering the old RPM's archive when creating the delta. */
int fillblock_filesystem(struct blocks *blks, struct block *blk, size_t id, size_t copy_cnt)
{
    int error = DRPM_ERR_OK;
    const struct cpio_file *cpio;
    unsigned char *buf_ptr;
    size_t len;
    uint64_t off;
    size_t i;
    size_t file_off;
    size_t read_len;
    struct open_file *file;
    bool prelinked;

    if (blks == NULL || blk == NULL)
        return DRPM_ERR_PROG;

    buf_ptr = blk->data.buffer;
    len = BLOCK_SIZE;
    off = id * BLOCK_SIZE;
    i = blks->cpio_files_index >= 0 ? blks->cpio_files_index : 0;

    for (cpio = blks->cpio_files + i; i > 0 && cpio->offset > off; i--, cpio--);

    for ( ; i < blks->cpio_files_len; i++, cpio++)
        if (cpio->offset <= off && cpio->offset + cpio->header_len + cpio->content_len > off)
            break;

    if (i == blks->cpio_files_len)
        return DRPM_ERR_PROG;

    if ((ssize_t)i != blks->cpio_files_index) {
        fill_cpio_header(blks, cpio->index);
        blks->cpio_files_index = i;
    }

    while (len > 0) {
        if (off < cpio->offset + cpio->header_len) {
            file_off = off - cpio->offset;
            read_len = MIN(len, cpio->header_len - file_off);
            memcpy(buf_ptr, blks->cpio_buffer + file_off, read_len);
            buf_ptr += read_len;
            off += read_len;
            len -= read_len;
            continue;
        }

        if (cpio->index < 0) {
            memset(buf_ptr, 0, len);
            len = 0;
            error = DRPM_ERR_OK;
            break;
        }

        if (off < cpio->offset + cpio->header_len + cpio->content_len) {
            file_off = off - (cpio->offset + cpio->header_len);
            if (S_ISLNK(blks->files[cpio->index].mode)) {
                read_len = MIN(len, cpio->content_len - file_off);
                if (file_off > strlen(blks->linkto))
                    memset(buf_ptr, 0, read_len);
                else
                    strncpy((char *)buf_ptr, blks->linkto + file_off, read_len);
            } else if (file_off < blks->files[cpio->index].size) {
                read_len = MIN(len, blks->files[cpio->index].size - file_off);
                file = get_open_file(blks, cpio->index);
                if (file == NULL) {
                    if ((error = open_new_file(blks, &prelinked, cpio->index)) != DRPM_ERR_OK)
                        break;
                    if (prelinked) {
                        blks->cpio_files_index = -1;
                        return fillblock_prelink(blks, blk, id, copy_cnt, cpio);
                    }
                    file = get_open_file(blks, cpio->index);
                }
                if (file->offset != (off_t)file_off && lseek(file->filedesc, file_off, SEEK_SET) != (off_t)file_off) {
                    error = DRPM_ERR_IO;
                    break;
                }
                if (read(file->filedesc, buf_ptr, read_len) != (ssize_t)read_len) {
                    error = DRPM_ERR_FORMAT;
                    break;
                }
                file->offset = file_off + read_len;
            } else {
                read_len = MIN(len, cpio->content_len - file_off);
                memset(buf_ptr, 0, read_len);
            }
            buf_ptr += read_len;
            off += read_len;
            len -= read_len;
            continue;
        }

        blks->cpio_files_index++;
        cpio++;
        fill_cpio_header(blks, cpio->index);
    }

    blk->id = id;
    blk->type = BLK_CORE_NOPAGE;

    return error;
}

/* if an installed file is modified by prelink, this will use the original */
int fillblock_prelink(struct blocks *blks, struct block *blk, size_t id, size_t copy_cnt, const struct cpio_file *cpio)
{
    int error = DRPM_ERR_OK;
    struct stat stats;
    uint64_t off = id * BLOCK_SIZE;
    int filedesc = -1;
    bool prelinked;
    unsigned char plnk_buf[128];
    size_t read_len;
    size_t id_orig = id;
    size_t len;
    unsigned char *buf_ptr;
    size_t file_off;
    const char *linkto;
    unsigned char blk_buf[BLOCK_SIZE];

    if (blks == NULL || blk == NULL || cpio == NULL)
        return DRPM_ERR_PROG;

    while (true) {
        while (cpio->offset > off)
            cpio--;

        if (cpio->index < 0 || cpio->content_len == 0 ||
            cpio->offset + cpio->header_len >= off ||
            S_ISLNK(blks->files[cpio->index].mode))
            break;

        if ((filedesc = open(blks->files[cpio->index].name, O_RDONLY)) < 0) {
            error = DRPM_ERR_IO;
            goto cleanup;
        }

        if (fstat(filedesc, &stats) != 0 || stats.st_size == blks->files[cpio->index].size)
            break;

        if ((error = is_prelinked(&prelinked, filedesc, plnk_buf, pread(filedesc, plnk_buf, 128, 0))) != DRPM_ERR_OK)
            goto cleanup;

        if (!prelinked)
            break;

        close(filedesc);
        filedesc = -1;

        do {
            id--;
            off = id * BLOCK_SIZE;
        } while (cpio->offset + cpio->header_len < off);
    }

    if (!(filedesc < 0)) {
        file_off = off - (cpio->offset + cpio->header_len);
        if (file_off > 0 && file_off < blks->files[cpio->index].size &&
            lseek(filedesc, file_off, SEEK_SET) == (off_t)-1) {
            error = DRPM_ERR_IO;
            goto cleanup;
        }
    }

    while (true) {
        len = BLOCK_SIZE;
        buf_ptr = blk->data.buffer;

        while (len > 0) {
            while (off >= cpio->offset + cpio->header_len + cpio->content_len) {
                if (!(filedesc < 0)) {
                    close(filedesc);
                    filedesc = -1;
                }
                cpio++;
            }

            if (off < cpio->offset + cpio->header_len) {
                file_off = off - cpio->offset;
                read_len = MIN(len, cpio->header_len - file_off);
                fill_cpio_header(blks, cpio->index);
                memcpy(buf_ptr, blks->cpio_buffer + file_off, read_len);
                buf_ptr += read_len;
                off += read_len;
                len -= read_len;
            }

            if (len == 0)
                break;

            if (cpio->index < 0) {
                memset(buf_ptr, 0, len);
                buf_ptr += len;
                off += len;
                len = 0;
            } else if (S_ISLNK(blks->files[cpio->index].mode)) {
                file_off = off - (cpio->offset + cpio->header_len);
                linkto = blks->files[cpio->index].linkto;
                read_len = MIN(len, strlen(linkto) < file_off ? 0 : strlen(linkto));
                if (read_len) {
                    memcpy(buf_ptr, linkto + file_off, read_len);
                    buf_ptr += read_len;
                    off += read_len;
                    len -= read_len;
                    file_off += read_len;
                }
                if (cpio->content_len > file_off) {
                    read_len = MIN(len, cpio->content_len - file_off);
                    if (read_len > 0) {
                        memset(buf_ptr, 0, read_len);
                        buf_ptr += read_len;
                        off += read_len;
                        len -= read_len;
                    }
                }
            } else if (cpio->content_len > 0) {
                file_off = off - (cpio->offset + cpio->header_len);
                if (file_off < blks->files[cpio->index].size) {
                    read_len = MIN(len, blks->files[cpio->index].size - file_off);

                    if (filedesc < 0) {
                        prelinked = false;
                        if ((filedesc = open(blks->files[cpio->index].name, O_RDONLY)) < 0) {
                            error = DRPM_ERR_IO;
                            goto cleanup;
                        } else if (fstat(filedesc, &stats) == 0 &&
                                   stats.st_size != blks->files[cpio->index].size) {
                            if ((error = is_prelinked(&prelinked, filedesc, plnk_buf, pread(filedesc, plnk_buf, 128, 0))) != DRPM_ERR_OK)
                                goto cleanup;
                            if (prelinked) {
                                close(filedesc);
                                if ((error = prelink_open(blks->files[cpio->index].name, &filedesc)) != DRPM_ERR_OK)
                                    goto cleanup;
                            }
                        }
                    }

                    if (read(filedesc, buf_ptr, read_len) != (ssize_t)read_len) {
                        error = DRPM_ERR_IO;
                        goto cleanup;
                    }

                    buf_ptr += read_len;
                    off += read_len;
                    len -= read_len;
                    file_off += read_len;
                }

                if (file_off >= blks->files[cpio->index].size) {
                    if (!(filedesc < 0)) {
                        close(filedesc);
                        filedesc = -1;
                    }
                    read_len = MIN(len, cpio->content_len - file_off);
                    if (read_len > 0)
                        memset(buf_ptr, 0, read_len);
                    buf_ptr += read_len;
                    off += read_len;
                    len -= read_len;
                }
            }
        }

        blk->type = BLK_CORE;
        blk->id = id;

        if (id == id_orig) {
            memcpy(blk_buf, blk->data.buffer, BLOCK_SIZE);
        } else if (blks->blocks_max[id] > copy_cnt ||
                   (blks->blocks_max[id] == copy_cnt && id > id_orig)) {
            if ((error = push_block(blks, blk, copy_cnt)) != DRPM_ERR_OK)
                goto cleanup;
        }

        if (filedesc < 0 || !prelinked)
            break;

        id++;
        off = id * BLOCK_SIZE;
    }

    if (id < id_orig) {
        error = DRPM_ERR_PROG;
        goto cleanup;
    }

    memcpy(blk->data.buffer, blk_buf, BLOCK_SIZE);
    blk->type = BLK_CORE;
    blk->id = id_orig;

cleanup:
    if (!(filedesc < 0))
        close(filedesc);

    return error;
}
