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

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#define MD5_BYTES 16
#define CHUNK_SIZE 1024

#define PAYLOAD_FORMAT_CPIO 0
#define PAYLOAD_FORMAT_XAR 1

struct drpm {
    char *filename;
    uint32_t version;
    uint32_t type;
    uint32_t comp;
    char *sequence;
    char *src_nevr;
    char *tgt_nevr;
    uint32_t tgt_size;
    char tgt_md5[MD5_BYTES * 2 + 1];
    uint32_t tgt_comp;
    char *tgt_comp_param;
    uint32_t tgt_header_len;
    uint32_t *adj_elems;
    char *tgt_lead;
    uint32_t payload_fmt_off;
    uint32_t *int_copies;
    uint32_t *ext_copies;
    uint64_t ext_data_len;
    uint64_t int_data_len;

    uint32_t adj_elems_size;
    uint32_t int_copies_size;
    uint32_t ext_copies_size;
};

//drpm_compstrm.c
struct compstrm;
int compstrm_destroy(struct compstrm **);
int compstrm_init(struct compstrm **, int, unsigned short);
int compstrm_write(struct compstrm *, size_t, const char *);
int compstrm_write_be32(struct compstrm *, uint32_t);
int compstrm_write_be64(struct compstrm *, uint64_t);

//drpm_decompstrm.c
struct decompstrm;
int decompstrm_destroy(struct decompstrm **);
int decompstrm_init(struct decompstrm **, int, uint32_t *);
int decompstrm_read(struct decompstrm *, size_t, char *);
int decompstrm_read_be32(struct decompstrm *, uint32_t *);
int decompstrm_read_be64(struct decompstrm *, uint64_t *);

//drpm_deltarpm.c
bool deltarpm_decode_comp(uint32_t, unsigned short *);
bool deltarpm_encode_comp(unsigned short, uint32_t *);

//drpm_read.c
int read_be32(int, uint32_t *);
int read_be64(int, uint64_t *);
int readdelta_rest(int, struct drpm *);
int readdelta_rpmonly(int, struct drpm *);
int readdelta_standard(int, struct drpm *);

//drpm_rpm.c
struct rpm;
int rpm_add_archive_to_md5(struct rpm, MD5_CTX *);
int rpm_add_header_to_md5(struct rpm, MD5_CTX *);
int rpm_add_lead_to_md5(struct rpm, MD5_CTX *);
int rpm_add_signature_to_md5(struct rpm, MD5_CTX *);
unsigned rpm_archive_read_chunk(struct rpm *, unsigned char *, unsigned);
int rpm_destroy(struct rpm *);
int rpm_fetch_header(struct rpm, unsigned char **, uint32_t *);
int rpm_fetch_lead_and_signature(struct rpm, unsigned char **, uint32_t *);
int rpm_get_comp(struct rpm, uint32_t *);
int rpm_get_comp_only(const char *, unsigned short *);
int rpm_get_nevr(struct rpm, char **);
int rpm_get_payload_format(struct rpm, unsigned short *);
int rpm_get_payload_format_offset(struct rpm, uint32_t *);
int rpm_patch_payload_format(struct rpm *, const char *);
int rpm_read(struct rpm *, const char *, bool);
uint32_t rpm_size_full(struct rpm);
uint32_t rpm_size_header(struct rpm);
int rpm_write(struct rpm, const char *, bool);

//drpm_utils.c
void create_be32(uint32_t, char *);
void create_be64(uint64_t, char *);
void dump_hex(char *, char *, size_t);
uint32_t parse_be32(char *);
uint64_t parse_be64(char *);

#endif
