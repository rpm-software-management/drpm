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

#ifndef _DRPM_PRIVATE_H_
#define _DRPM_PRIVATE_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h> // DEBUG

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <openssl/md5.h>

#define CHUNK_SIZE 1024

#define DIGESTALGO_MD5 0
#define DIGESTALGO_SHA256 1

#define RPM_PAYLOAD_FORMAT_DRPM 0
#define RPM_PAYLOAD_FORMAT_CPIO 1
#define RPM_PAYLOAD_FORMAT_XAR 2

#define RPM_ARCHIVE_DONT_READ 0
#define RPM_ARCHIVE_READ_UNCOMP 1
#define RPM_ARCHIVE_READ_DECOMP 2

#define MIN(x,y) (((x) < (y)) ? (x) : (y))
#define MAX(x,y) (((x) > (y)) ? (x) : (y))

#define TWOS_COMPLEMENT(x) (~(x) + 1)

#define PADDING(offset, align) ((((align) - ((offset) % (align))) % (align)))

struct drpm {
    char *filename;
    uint32_t version;
    uint32_t type;
    uint32_t comp;
    char *sequence;
    char *src_nevr;
    char *tgt_nevr;
    uint32_t tgt_size;
    char tgt_md5[MD5_DIGEST_LENGTH * 2 + 1];
    uint32_t tgt_comp;
    char *tgt_comp_param;
    uint32_t tgt_header_len;
    uint32_t *offadj_elems;
    char *tgt_leadsig;
    uint32_t payload_fmt_off;
    uint32_t *int_copies;
    uint32_t *ext_copies;
    uint64_t ext_data_len;
    uint64_t int_data_len;

    uint32_t offadj_elems_size;
    uint32_t int_copies_size;
    uint32_t ext_copies_size;
};

struct drpm_make_options {
    bool rpm_only;
    unsigned short version;
    bool comp_from_rpm;
    unsigned short comp;
    unsigned short comp_level;
    bool addblk;
    unsigned short addblk_comp;
    unsigned short addblk_comp_level;
    char *seqfile;
    char *oldrpmprint;
    char *oldpatchrpm;
    unsigned mbytes;
};

struct deltarpm;
struct file_info;

//drpm_compstrm.c
struct compstrm;
//drpm_decompstrm.c
struct decompstrm;
//drpm_make.c
struct rpm_patches;
//drpm_rpm.c
struct rpm;
//drpm_search.c
struct hash;
struct sfxsrt;

// DEBUG
const char *type2str(unsigned short type);
const char *comp2str(unsigned short comp);

//drpm_compstrm.c
int compstrm_destroy(struct compstrm **);
int compstrm_finish(struct compstrm *, unsigned char **, size_t *);
int compstrm_init(struct compstrm **, int, unsigned short, int);
int compstrm_write(struct compstrm *, size_t, const void *);
int compstrm_write_be32(struct compstrm *, uint32_t);
int compstrm_write_be64(struct compstrm *, uint64_t);

//drpm_decompstrm.c
int decompstrm_destroy(struct decompstrm **);
int decompstrm_get_comp_size(struct decompstrm *, size_t *);
int decompstrm_init(struct decompstrm **, int, unsigned short *, MD5_CTX *);
int decompstrm_read(struct decompstrm *, size_t, void *);
int decompstrm_read_be32(struct decompstrm *, uint32_t *);
int decompstrm_read_be64(struct decompstrm *, uint64_t *);
int decompstrm_read_until_eof(struct decompstrm *, size_t *, unsigned char **);

//drpm_deltarpm.c
bool deltarpm_decode_comp(uint32_t, unsigned short *, unsigned short *);
bool deltarpm_encode_comp(uint32_t *, unsigned short, unsigned short);
void free_deltarpm(struct deltarpm *);

//drpm_diff.c
int make_diff(const unsigned char *, size_t, const unsigned char *, size_t,
              const unsigned char ***, uint64_t *, uint32_t **, uint32_t *,
              uint32_t **, uint32_t *, unsigned char **, uint32_t *,
              unsigned short, int);

//drpm_make.c
int fill_nodiff_deltarpm(struct deltarpm *, const char *, bool);
int parse_cpio_from_rpm_filedata(struct rpm *, unsigned char **, size_t *,
                                 unsigned char **, uint32_t *,
                                 uint32_t **, uint32_t *,
                                 const struct rpm_patches *);
int patches_check_nevr(const struct rpm_patches *, const char *);
int patches_destroy(struct rpm_patches **);
int patches_read(const char *, const char *, struct rpm_patches **);

//drpm_read.c
int deltarpm_to_drpm(const struct deltarpm *, struct drpm *);
void drpm_free(struct drpm *);
int read_be32(int, uint32_t *);
int read_be64(int, uint64_t *);
int read_deltarpm(struct deltarpm *, const char *);

//drpm_rpm.c
int rpm_archive_read_chunk(struct rpm *, void *, size_t);
int rpm_archive_rewind(struct rpm *);
int rpm_destroy(struct rpm **);
int rpm_fetch_archive(struct rpm *, unsigned char **, size_t *);
int rpm_fetch_header(struct rpm *, unsigned char **, uint32_t *);
int rpm_fetch_lead_and_signature(struct rpm *, unsigned char **, uint32_t *);
int rpm_find_payload_format_offset(struct rpm *, uint32_t *);
int rpm_get_comp(struct rpm *, unsigned short *);
int rpm_get_comp_level(struct rpm *, unsigned short *);
int rpm_get_digest_algo(struct rpm *, unsigned short *);
int rpm_get_file_info(struct rpm *, struct file_info **, size_t *, bool *);
int rpm_get_nevr(struct rpm *, char **);
int rpm_get_payload_format(struct rpm *, unsigned short *);
int rpm_patch_payload_format(struct rpm *, const char *);
int rpm_read(struct rpm **, const char *, int, unsigned short *,
             unsigned char *, unsigned char *);
int rpm_signature_empty(struct rpm *);
int rpm_signature_reload(struct rpm *);
int rpm_signature_set_md5(struct rpm *, unsigned char *);
int rpm_signature_set_size(struct rpm *, uint32_t);
uint32_t rpm_size_full(struct rpm *);
uint32_t rpm_size_header(struct rpm *);
int rpm_write(struct rpm *, const char *, bool);
int rpmdb_fetch_header(const char *, const char *, unsigned char **, size_t *);

//drpm_search.c
int hash_create(struct hash **, const unsigned char *, size_t);
void hash_free(struct hash **);
size_t hash_search(struct hash *, const unsigned char *, size_t,
                   const unsigned char *, size_t, size_t, size_t, size_t *, size_t *);
int sfxsrt_create(struct sfxsrt **, const unsigned char *, size_t);
void sfxsrt_free(struct sfxsrt **);
size_t sfxsrt_search(struct sfxsrt *, const unsigned char *, size_t,
                     const unsigned char *, size_t, size_t, size_t, size_t *, size_t *);

//drpm_utils.c
void create_be32(uint32_t, unsigned char *);
void create_be64(uint64_t, unsigned char *);
void dump_hex(char *, const unsigned char *, size_t);
int md5_update_be32(MD5_CTX *, uint32_t);
uint16_t parse_be16(const unsigned char *);
uint32_t parse_be32(const unsigned char *);
uint64_t parse_be64(const unsigned char *);
ssize_t parse_hex(unsigned char *, const char *);
ssize_t parse_hexnum(const char *, size_t);
bool parse_md5(unsigned char *, const char *);
bool parse_sha256(unsigned char *, const char *);
bool resize16(void **, size_t, size_t);
bool resize32(void **, size_t, size_t);

//drpm_write.c
int write_be32(int, uint32_t);
int write_be64(int, uint64_t);
int write_deltarpm(struct deltarpm *);
int write_seqfile(struct deltarpm *, const char *);

struct deltarpm {
    const char *filename;
    unsigned short type;
    unsigned short comp;
    unsigned short comp_level;
    union {
        struct rpm *tgt_rpm;
        char *tgt_nevr;
    } head;
    unsigned short version;
    char *src_nevr;
    uint32_t sequence_len;
    unsigned char *sequence;
    unsigned char tgt_md5[MD5_DIGEST_LENGTH];
    uint32_t tgt_size;
    unsigned short tgt_comp;
    unsigned short tgt_comp_level;
    uint32_t tgt_comp_param_len;
    unsigned char *tgt_comp_param;
    uint32_t tgt_header_len;
    uint32_t offadj_elems_count;
    uint32_t *offadj_elems;
    uint32_t tgt_leadsig_len;
    unsigned char *tgt_leadsig;
    uint32_t payload_fmt_off;
    uint32_t int_copies_count;
    uint32_t ext_copies_count;
    uint32_t *int_copies;
    uint32_t *ext_copies;
    uint64_t ext_data_len;
    uint32_t add_data_len;
    unsigned char *add_data;
    uint64_t int_data_len;
    bool int_data_as_ptrs;
    union {
        unsigned char *bytes;
        const unsigned char **ptrs;
    } int_data;
};

struct file_info {
    char *name;
    uint32_t flags;
    char *md5;
    uint16_t rdev;
    uint32_t size;
    uint16_t mode;
    uint32_t verify;
    char *linkto;
    uint32_t color;
};

#endif
