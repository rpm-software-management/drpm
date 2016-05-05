/*
    Authors:
        Matej Chalk <mchalk@redhat.com>

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

#include "../src/drpm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <sys/stat.h>
#include <openssl/md5.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#define DELTARPM_COUNT 6

#define DELTARPM_NODIFF "nodiff.drpm"
#define DELTARPM_IDENTITY "identity.drpm"
#define DELTARPM_RPMONLY "rpmonly.drpm"
#define DELTARPM_STANDARD "standard.drpm"
#define DELTARPM_RPMONLY_NOADDBLK "rpmonly-noaddblk.drpm"
#define DELTARPM_STANDARD_LZIP "standard-lzip.drpm"

#define OLDRPM_1 "drpm-old.rpm"
#define NEWRPM_1 "drpm-new.rpm"
#define OLDRPM_2 "cmocka-old.rpm"
#define NEWRPM_2 "cmocka-new.rpm"

#define RPMOUT_STANDARD "standard.rpm"
#define RPMOUT_RPMONLY_NOADDBLK "rpmonly-noaddblk.rpm"
#define RPMOUT_STANDARD_LZIP "standard-lzip.rpm"

#define SEQFILE "seqfile.txt"

struct read_deltas {
    unsigned short index;
    drpm *deltas[DELTARPM_COUNT];
    char *filenames[DELTARPM_COUNT];
    char *src_nevrs[DELTARPM_COUNT];
    char *tgt_nevrs[DELTARPM_COUNT];
    char *sequences[DELTARPM_COUNT];
    char *tgt_md5s[DELTARPM_COUNT];
    char *tgt_leads[DELTARPM_COUNT];
    unsigned long *int_copies_arrays[DELTARPM_COUNT];
    unsigned long *ext_copies_arrays[DELTARPM_COUNT];
};

static off_t filesize(const char *path)
{
    struct stat stats;

    if (stat(path, &stats) != 0)
        return -1;

    return stats.st_size;
}

/***************************** drpm_make ******************************/

static int make_setup(void **state)
{
    drpm_make_options *opts;

    if (drpm_make_options_init(&opts) != DRPM_ERR_OK)
        return -1;

    *state = opts;

    return 0;
}

static int make_teardown(void **state)
{
    drpm_make_options *opts = *state;

    if (drpm_make_options_destroy(&opts) != DRPM_ERR_OK)
        return -1;

    return 0;
}

static void make_nodiff(void **state)
{
    drpm_make_options *opts = *state;
    assert_int_equal(DRPM_ERR_OK, drpm_make_options_defaults(opts));

    assert_int_equal(DRPM_ERR_OK, drpm_make_options_set_type(opts, DRPM_TYPE_RPMONLY));

    assert_int_equal(DRPM_ERR_OK, drpm_make(OLDRPM_1, NULL, DELTARPM_NODIFF, opts));
}

static void make_identity(void **state)
{
    drpm_make_options *opts = *state;
    assert_int_equal(DRPM_ERR_OK, drpm_make_options_defaults(opts));

    assert_int_equal(DRPM_ERR_OK, drpm_make_options_set_version(opts, 2));
    assert_int_equal(DRPM_ERR_OK, drpm_make_options_set_delta_comp(opts, DRPM_COMP_NONE, DRPM_COMP_LEVEL_DEFAULT));

    assert_int_equal(DRPM_ERR_OK, drpm_make(NULL, NEWRPM_1, DELTARPM_IDENTITY, opts));
}

static void make_rpmonly(void **state)
{
    drpm_make_options *opts = *state;
    assert_int_equal(DRPM_ERR_OK, drpm_make_options_defaults(opts));

    assert_int_equal(DRPM_ERR_OK, drpm_make_options_set_type(opts, DRPM_TYPE_RPMONLY));
    assert_int_equal(DRPM_ERR_OK, drpm_make_options_set_delta_comp(opts, DRPM_COMP_BZIP2, 7));
    assert_int_equal(DRPM_ERR_OK, drpm_make_options_set_addblk_comp(opts, DRPM_COMP_LZMA, DRPM_COMP_LEVEL_DEFAULT));

    assert_int_equal(DRPM_ERR_OK, drpm_make(OLDRPM_2, NEWRPM_2, DELTARPM_RPMONLY, opts));
}

static void make_standard(void **state)
{
    drpm_make_options *opts = *state;
    assert_int_equal(DRPM_ERR_OK, drpm_make_options_defaults(opts));

    assert_int_equal(DRPM_ERR_OK, drpm_make_options_set_seqfile(opts, SEQFILE));;

    assert_int_equal(DRPM_ERR_OK, drpm_make(OLDRPM_1, NEWRPM_1, DELTARPM_STANDARD, opts));
}

static void make_rpmonly_noaddblk(void **state)
{
    drpm_make_options *opts = *state;
    assert_int_equal(DRPM_ERR_OK, drpm_make_options_defaults(opts));

    assert_int_equal(DRPM_ERR_OK, drpm_make_options_set_type(opts, DRPM_TYPE_RPMONLY));
    assert_int_equal(DRPM_ERR_OK, drpm_make_options_set_delta_comp(opts, DRPM_COMP_GZIP, DRPM_COMP_LEVEL_DEFAULT));
    assert_int_equal(DRPM_ERR_OK, drpm_make_options_forbid_addblk(opts));

    assert_int_equal(DRPM_ERR_OK, drpm_make(OLDRPM_2, NEWRPM_2, DELTARPM_RPMONLY_NOADDBLK, opts));
}

static void make_standard_lzip(void **state)
{
    drpm_make_options *opts = *state;
    assert_int_equal(DRPM_ERR_OK, drpm_make_options_defaults(opts));

    assert_int_equal(DRPM_ERR_OK, drpm_make_options_set_delta_comp(opts, DRPM_COMP_LZIP, DRPM_COMP_LEVEL_DEFAULT));;

    assert_int_equal(DRPM_ERR_OK, drpm_make(OLDRPM_2, NEWRPM_2, DELTARPM_STANDARD_LZIP, opts));
}

/***************************** drpm_read ******************************/

static int read_setup(void **state)
{
    const struct read_deltas drpms_init = {
        .index = 0,
        .deltas = {NULL},
        .filenames = {NULL},
        .src_nevrs = {NULL},
        .tgt_nevrs = {NULL},
        .sequences = {NULL},
        .tgt_md5s = {NULL},
        .tgt_leads = {NULL},
        .int_copies_arrays = {NULL},
        .ext_copies_arrays = {NULL},
    };
    struct read_deltas *drpms;

    if ((drpms = malloc(sizeof(struct read_deltas))) == NULL)
        return -1;

    *drpms = drpms_init;
    *state = drpms;

    return 0;
}

static int read_teardown(void **state)
{
    struct read_deltas *drpms = *state;

    while (drpms->index-- > 0) {
        drpm_destroy(&drpms->deltas[drpms->index]);
        free(drpms->filenames[drpms->index]);
        free(drpms->src_nevrs[drpms->index]);
        free(drpms->tgt_nevrs[drpms->index]);
        free(drpms->sequences[drpms->index]);
        free(drpms->tgt_md5s[drpms->index]);
        free(drpms->tgt_leads[drpms->index]);
        free(drpms->int_copies_arrays[drpms->index]);
        free(drpms->ext_copies_arrays[drpms->index]);
    }

    free(drpms);

    return 0;
}

static void read_nodiff(void **state)
{
    struct read_deltas *drpms = *state;
    unsigned index = drpms->index++;
    drpm *delta = NULL;
    const char *delta_name = DELTARPM_NODIFF;

    char *filename;
    unsigned version;
    unsigned type;
    unsigned comp;
    char *sequence;
    char *src_nevr;
    char *tgt_nevr;
    unsigned long tgt_size;
    char *tgt_md5;
    unsigned tgt_comp;
    unsigned long tgt_header_len;
    char *tgt_lead;
    unsigned long *int_copies;
    unsigned long int_copies_size;
    unsigned long *ext_copies;
    unsigned long ext_copies_size;
    unsigned long long ext_data_len;
    unsigned long long int_data_len;

    assert_int_equal(DRPM_ERR_OK, drpm_read(&drpms->deltas[index], delta_name));
    delta = drpms->deltas[index];

    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_VERSION, &version));
    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_TYPE, &type));
    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_COMP, &comp));
    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_TGTCOMP, &tgt_comp));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ulong(delta, DRPM_TAG_TGTSIZE, &tgt_size));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ulong(delta, DRPM_TAG_TGTHEADERLEN, &tgt_header_len));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ullong(delta, DRPM_TAG_EXTDATALEN, &ext_data_len));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ullong(delta, DRPM_TAG_INTDATALEN, &int_data_len));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_FILENAME, &drpms->filenames[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_SEQUENCE, &drpms->sequences[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_SRCNEVR, &drpms->src_nevrs[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_TGTNEVR, &drpms->tgt_nevrs[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_TGTMD5, &drpms->tgt_md5s[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_TGTLEAD, &drpms->tgt_leads[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ulong_array(delta, DRPM_TAG_INTCOPIES, &drpms->int_copies_arrays[index], &int_copies_size));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ulong_array(delta, DRPM_TAG_EXTCOPIES, &drpms->ext_copies_arrays[index], &ext_copies_size));
    filename = drpms->filenames[index];
    sequence = drpms->sequences[index];
    src_nevr = drpms->src_nevrs[index];
    tgt_nevr = drpms->tgt_nevrs[index];
    tgt_md5 = drpms->tgt_md5s[index];
    tgt_lead = drpms->tgt_leads[index];
    int_copies = drpms->int_copies_arrays[index];
    ext_copies = drpms->ext_copies_arrays[index];

    assert_non_null(filename);
    assert_non_null(sequence);
    assert_non_null(src_nevr);
    assert_non_null(tgt_nevr);
    assert_non_null(tgt_md5);
    assert_non_null(tgt_lead);
    assert_null(int_copies);
    assert_null(ext_copies);

    assert_string_equal(delta_name, filename);
    assert_int_equal(DRPM_TYPE_RPMONLY, type);
    assert_int_equal(3, version);
    assert_int_equal(MD5_DIGEST_LENGTH * 2, strlen(sequence));
    assert_string_equal(src_nevr, tgt_nevr);
    assert_int_equal(filesize(OLDRPM_1), tgt_size);
    assert_int_equal(MD5_DIGEST_LENGTH * 2, strlen(tgt_md5));
    assert_int_not_equal(0, tgt_header_len);
    assert_not_in_range(strlen(tgt_lead), 0, (96 + 16) - 1);
    assert_int_equal(0, int_copies_size);
    assert_int_equal(0, ext_copies_size);
    assert_int_equal(0, int_data_len);
    assert_int_equal(0, ext_data_len);
}

static void read_identity(void **state)
{
    struct read_deltas *drpms = *state;
    unsigned index = drpms->index++;
    drpm *delta = NULL;
    const char *delta_name = DELTARPM_IDENTITY;

    char *filename;
    unsigned version;
    unsigned type;
    unsigned comp;
    char *sequence;
    char *src_nevr;
    char *tgt_nevr;
    unsigned long tgt_size;
    char *tgt_md5;
    unsigned tgt_comp;
    unsigned long tgt_header_len;
    char *tgt_lead;
    unsigned long *int_copies;
    unsigned long int_copies_size;
    unsigned long *ext_copies;
    unsigned long ext_copies_size;
    unsigned long long ext_data_len;
    unsigned long long int_data_len;

    assert_int_equal(DRPM_ERR_OK, drpm_read(&drpms->deltas[index], delta_name));
    delta = drpms->deltas[index];

    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_VERSION, &version));
    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_TYPE, &type));
    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_COMP, &comp));
    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_TGTCOMP, &tgt_comp));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ulong(delta, DRPM_TAG_TGTSIZE, &tgt_size));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ulong(delta, DRPM_TAG_TGTHEADERLEN, &tgt_header_len));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ullong(delta, DRPM_TAG_EXTDATALEN, &ext_data_len));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ullong(delta, DRPM_TAG_INTDATALEN, &int_data_len));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_FILENAME, &drpms->filenames[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_SEQUENCE, &drpms->sequences[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_SRCNEVR, &drpms->src_nevrs[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_TGTNEVR, &drpms->tgt_nevrs[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_TGTMD5, &drpms->tgt_md5s[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_TGTLEAD, &drpms->tgt_leads[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ulong_array(delta, DRPM_TAG_INTCOPIES, &drpms->int_copies_arrays[index], &int_copies_size));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ulong_array(delta, DRPM_TAG_EXTCOPIES, &drpms->ext_copies_arrays[index], &ext_copies_size));
    filename = drpms->filenames[index];
    sequence = drpms->sequences[index];
    src_nevr = drpms->src_nevrs[index];
    tgt_nevr = drpms->tgt_nevrs[index];
    tgt_md5 = drpms->tgt_md5s[index];
    tgt_lead = drpms->tgt_leads[index];
    int_copies = drpms->int_copies_arrays[index];
    ext_copies = drpms->ext_copies_arrays[index];

    assert_non_null(filename);
    assert_non_null(sequence);
    assert_non_null(src_nevr);
    assert_non_null(tgt_nevr);
    assert_non_null(tgt_md5);
    assert_non_null(tgt_lead);

    assert_string_equal(delta_name, filename);
    assert_int_equal(DRPM_TYPE_STANDARD, type);
    assert_int_equal(2, version);
    assert_int_equal(DRPM_COMP_NONE, comp);
    assert_not_in_range(strlen(sequence), 0, (MD5_DIGEST_LENGTH * 2) - 1);
    assert_string_equal(src_nevr, tgt_nevr);
    assert_int_equal(filesize(NEWRPM_1), tgt_size);
    assert_int_equal(MD5_DIGEST_LENGTH * 2, strlen(tgt_md5));
    assert_int_equal(0, tgt_header_len);
    assert_not_in_range(strlen(tgt_lead), 0, (96 + 16) - 1);
    assert_true(int_copies_size % 2 == 0);
    assert_true(ext_copies_size % 2 == 0);

    unsigned long int_copies_count = int_copies_size / 2;
    unsigned long ext_copies_count = ext_copies_size / 2;
    unsigned long count;
    unsigned long long off;

    count = 0;
    off = 0;
    for (unsigned long i = 0; i < int_copies_count; i++) {
        count += int_copies[2 * i];
        assert_false(count > ext_copies_count);
        off += int_copies[2 * i + 1];
        assert_false(off > int_data_len);
    }

    off = 0;
    for (unsigned long i = 0; i < ext_copies_count; i++) {
        off += (int32_t)ext_copies[2 * i];
        assert_false(off > ext_data_len);
        off += ext_copies[2 * i + 1];
        assert_int_not_equal(0, off);
        assert_false(off > ext_data_len);
    }
}

static void read_rpmonly(void **state)
{
    struct read_deltas *drpms = *state;
    unsigned index = drpms->index++;
    drpm *delta = NULL;
    const char *delta_name = DELTARPM_RPMONLY;

    char *filename;
    unsigned version;
    unsigned type;
    unsigned comp;
    char *sequence;
    char *src_nevr;
    char *tgt_nevr;
    unsigned long tgt_size;
    char *tgt_md5;
    unsigned tgt_comp;
    unsigned long tgt_header_len;
    char *tgt_lead;
    unsigned long *int_copies;
    unsigned long int_copies_size;
    unsigned long *ext_copies;
    unsigned long ext_copies_size;
    unsigned long long ext_data_len;
    unsigned long long int_data_len;

    assert_int_equal(DRPM_ERR_OK, drpm_read(&drpms->deltas[index], delta_name));
    delta = drpms->deltas[index];

    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_VERSION, &version));
    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_TYPE, &type));
    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_COMP, &comp));
    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_TGTCOMP, &tgt_comp));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ulong(delta, DRPM_TAG_TGTSIZE, &tgt_size));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ulong(delta, DRPM_TAG_TGTHEADERLEN, &tgt_header_len));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ullong(delta, DRPM_TAG_EXTDATALEN, &ext_data_len));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ullong(delta, DRPM_TAG_INTDATALEN, &int_data_len));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_FILENAME, &drpms->filenames[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_SEQUENCE, &drpms->sequences[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_SRCNEVR, &drpms->src_nevrs[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_TGTNEVR, &drpms->tgt_nevrs[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_TGTMD5, &drpms->tgt_md5s[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_TGTLEAD, &drpms->tgt_leads[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ulong_array(delta, DRPM_TAG_INTCOPIES, &drpms->int_copies_arrays[index], &int_copies_size));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ulong_array(delta, DRPM_TAG_EXTCOPIES, &drpms->ext_copies_arrays[index], &ext_copies_size));
    filename = drpms->filenames[index];
    sequence = drpms->sequences[index];
    src_nevr = drpms->src_nevrs[index];
    tgt_nevr = drpms->tgt_nevrs[index];
    tgt_md5 = drpms->tgt_md5s[index];
    tgt_lead = drpms->tgt_leads[index];
    int_copies = drpms->int_copies_arrays[index];
    ext_copies = drpms->ext_copies_arrays[index];

    assert_non_null(filename);
    assert_non_null(sequence);
    assert_non_null(src_nevr);
    assert_non_null(tgt_nevr);
    assert_non_null(tgt_md5);
    assert_non_null(tgt_lead);

    assert_string_equal(delta_name, filename);
    assert_int_equal(DRPM_TYPE_RPMONLY, type);
    assert_int_equal(3, version);
    assert_int_equal(DRPM_COMP_BZIP2, comp);
    assert_int_equal(MD5_DIGEST_LENGTH * 2, strlen(sequence));
    assert_int_equal(filesize(NEWRPM_2), tgt_size);
    assert_int_equal(MD5_DIGEST_LENGTH * 2, strlen(tgt_md5));
    assert_int_not_equal(0, tgt_header_len);
    assert_not_in_range(strlen(tgt_lead), 0, (96 + 16) - 1);
    assert_true(int_copies_size % 2 == 0);
    assert_true(ext_copies_size % 2 == 0);

    unsigned long int_copies_count = int_copies_size / 2;
    unsigned long ext_copies_count = ext_copies_size / 2;
    unsigned long count;
    unsigned long long off;

    count = 0;
    off = 0;
    for (unsigned long i = 0; i < int_copies_count; i++) {
        count += int_copies[2 * i];
        assert_false(count > ext_copies_count);
        off += int_copies[2 * i + 1];
        assert_false(off > int_data_len);
    }

    off = 0;
    for (unsigned long i = 0; i < ext_copies_count; i++) {
        off += (int32_t)ext_copies[2 * i];
        assert_false(off > ext_data_len);
        off += ext_copies[2 * i + 1];
        assert_int_not_equal(0, off);
        assert_false(off > ext_data_len);
    }
}

static void read_standard(void **state)
{
    struct read_deltas *drpms = *state;
    unsigned index = drpms->index++;
    drpm *delta = NULL;
    const char *delta_name = DELTARPM_STANDARD;

    char *filename;
    unsigned version;
    unsigned type;
    unsigned comp;
    char *sequence;
    char *src_nevr;
    char *tgt_nevr;
    unsigned long tgt_size;
    char *tgt_md5;
    unsigned tgt_comp;
    unsigned long tgt_header_len;
    char *tgt_lead;
    unsigned long *int_copies;
    unsigned long int_copies_size;
    unsigned long *ext_copies;
    unsigned long ext_copies_size;
    unsigned long long ext_data_len;
    unsigned long long int_data_len;

    assert_int_equal(DRPM_ERR_OK, drpm_read(&drpms->deltas[index], delta_name));
    delta = drpms->deltas[index];

    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_VERSION, &version));
    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_TYPE, &type));
    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_COMP, &comp));
    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_TGTCOMP, &tgt_comp));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ulong(delta, DRPM_TAG_TGTSIZE, &tgt_size));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ulong(delta, DRPM_TAG_TGTHEADERLEN, &tgt_header_len));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ullong(delta, DRPM_TAG_EXTDATALEN, &ext_data_len));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ullong(delta, DRPM_TAG_INTDATALEN, &int_data_len));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_FILENAME, &drpms->filenames[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_SEQUENCE, &drpms->sequences[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_SRCNEVR, &drpms->src_nevrs[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_TGTNEVR, &drpms->tgt_nevrs[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_TGTMD5, &drpms->tgt_md5s[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_TGTLEAD, &drpms->tgt_leads[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ulong_array(delta, DRPM_TAG_INTCOPIES, &drpms->int_copies_arrays[index], &int_copies_size));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ulong_array(delta, DRPM_TAG_EXTCOPIES, &drpms->ext_copies_arrays[index], &ext_copies_size));
    filename = drpms->filenames[index];
    sequence = drpms->sequences[index];
    src_nevr = drpms->src_nevrs[index];
    tgt_nevr = drpms->tgt_nevrs[index];
    tgt_md5 = drpms->tgt_md5s[index];
    tgt_lead = drpms->tgt_leads[index];
    int_copies = drpms->int_copies_arrays[index];
    ext_copies = drpms->ext_copies_arrays[index];

    assert_non_null(filename);
    assert_non_null(sequence);
    assert_non_null(src_nevr);
    assert_non_null(tgt_nevr);
    assert_non_null(tgt_md5);
    assert_non_null(tgt_lead);

    assert_string_equal(delta_name, filename);
    assert_int_equal(DRPM_TYPE_STANDARD, type);
    assert_int_equal(3, version);
    assert_int_equal(tgt_comp, comp);
    assert_not_in_range(strlen(sequence), 0, (MD5_DIGEST_LENGTH * 2) - 1);
    assert_int_equal(filesize(NEWRPM_1), tgt_size);
    assert_int_equal(MD5_DIGEST_LENGTH * 2, strlen(tgt_md5));
    assert_int_equal(0, tgt_header_len);
    assert_not_in_range(strlen(tgt_lead), 0, (96 + 16) - 1);
    assert_true(int_copies_size % 2 == 0);
    assert_true(ext_copies_size % 2 == 0);

    unsigned long int_copies_count = int_copies_size / 2;
    unsigned long ext_copies_count = ext_copies_size / 2;
    unsigned long count;
    unsigned long long off;

    count = 0;
    off = 0;
    for (unsigned long i = 0; i < int_copies_count; i++) {
        count += int_copies[2 * i];
        assert_false(count > ext_copies_count);
        off += int_copies[2 * i + 1];
        assert_false(off > int_data_len);
    }

    off = 0;
    for (unsigned long i = 0; i < ext_copies_count; i++) {
        off += (int32_t)ext_copies[2 * i];
        assert_false(off > ext_data_len);
        off += ext_copies[2 * i + 1];
        assert_int_not_equal(0, off);
        assert_false(off > ext_data_len);
    }
}

static void read_rpmonly_noaddblk(void **state)
{
    struct read_deltas *drpms = *state;
    unsigned index = drpms->index++;
    drpm *delta = NULL;
    const char *delta_name = DELTARPM_RPMONLY_NOADDBLK;

    char *filename;
    unsigned version;
    unsigned type;
    unsigned comp;
    char *sequence;
    char *src_nevr;
    char *tgt_nevr;
    unsigned long tgt_size;
    char *tgt_md5;
    unsigned tgt_comp;
    unsigned long tgt_header_len;
    char *tgt_lead;
    unsigned long *int_copies;
    unsigned long int_copies_size;
    unsigned long *ext_copies;
    unsigned long ext_copies_size;
    unsigned long long ext_data_len;
    unsigned long long int_data_len;

    assert_int_equal(DRPM_ERR_OK, drpm_read(&drpms->deltas[index], delta_name));
    delta = drpms->deltas[index];

    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_VERSION, &version));
    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_TYPE, &type));
    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_COMP, &comp));
    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_TGTCOMP, &tgt_comp));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ulong(delta, DRPM_TAG_TGTSIZE, &tgt_size));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ulong(delta, DRPM_TAG_TGTHEADERLEN, &tgt_header_len));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ullong(delta, DRPM_TAG_EXTDATALEN, &ext_data_len));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ullong(delta, DRPM_TAG_INTDATALEN, &int_data_len));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_FILENAME, &drpms->filenames[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_SEQUENCE, &drpms->sequences[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_SRCNEVR, &drpms->src_nevrs[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_TGTNEVR, &drpms->tgt_nevrs[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_TGTMD5, &drpms->tgt_md5s[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_TGTLEAD, &drpms->tgt_leads[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ulong_array(delta, DRPM_TAG_INTCOPIES, &drpms->int_copies_arrays[index], &int_copies_size));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ulong_array(delta, DRPM_TAG_EXTCOPIES, &drpms->ext_copies_arrays[index], &ext_copies_size));
    filename = drpms->filenames[index];
    sequence = drpms->sequences[index];
    src_nevr = drpms->src_nevrs[index];
    tgt_nevr = drpms->tgt_nevrs[index];
    tgt_md5 = drpms->tgt_md5s[index];
    tgt_lead = drpms->tgt_leads[index];
    int_copies = drpms->int_copies_arrays[index];
    ext_copies = drpms->ext_copies_arrays[index];

    assert_non_null(filename);
    assert_non_null(sequence);
    assert_non_null(src_nevr);
    assert_non_null(tgt_nevr);
    assert_non_null(tgt_md5);
    assert_non_null(tgt_lead);

    assert_string_equal(delta_name, filename);
    assert_int_equal(DRPM_TYPE_RPMONLY, type);
    assert_int_equal(3, version);
    assert_int_equal(DRPM_COMP_GZIP, comp);
    assert_int_equal(MD5_DIGEST_LENGTH * 2, strlen(sequence));
    assert_int_equal(filesize(NEWRPM_2), tgt_size);
    assert_int_equal(MD5_DIGEST_LENGTH * 2, strlen(tgt_md5));
    assert_int_not_equal(0, tgt_header_len);
    assert_not_in_range(strlen(tgt_lead), 0, (96 + 16) - 1);
    assert_true(int_copies_size % 2 == 0);
    assert_true(ext_copies_size % 2 == 0);

    unsigned long int_copies_count = int_copies_size / 2;
    unsigned long ext_copies_count = ext_copies_size / 2;
    unsigned long count;
    unsigned long long off;

    count = 0;
    off = 0;
    for (unsigned long i = 0; i < int_copies_count; i++) {
        count += int_copies[2 * i];
        assert_false(count > ext_copies_count);
        off += int_copies[2 * i + 1];
        assert_false(off > int_data_len);
    }

    off = 0;
    for (unsigned long i = 0; i < ext_copies_count; i++) {
        off += (int32_t)ext_copies[2 * i];
        assert_false(off > ext_data_len);
        off += ext_copies[2 * i + 1];
        assert_int_not_equal(0, off);
        assert_false(off > ext_data_len);
    }
}

static void read_standard_lzip(void **state)
{
    struct read_deltas *drpms = *state;
    unsigned index = drpms->index++;
    drpm *delta = NULL;
    const char *delta_name = DELTARPM_STANDARD_LZIP;

    char *filename;
    unsigned version;
    unsigned type;
    unsigned comp;
    char *sequence;
    char *src_nevr;
    char *tgt_nevr;
    unsigned long tgt_size;
    char *tgt_md5;
    unsigned tgt_comp;
    unsigned long tgt_header_len;
    char *tgt_lead;
    unsigned long *int_copies;
    unsigned long int_copies_size;
    unsigned long *ext_copies;
    unsigned long ext_copies_size;
    unsigned long long ext_data_len;
    unsigned long long int_data_len;

    assert_int_equal(DRPM_ERR_OK, drpm_read(&drpms->deltas[index], delta_name));
    delta = drpms->deltas[index];

    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_VERSION, &version));
    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_TYPE, &type));
    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_COMP, &comp));
    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_TGTCOMP, &tgt_comp));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ulong(delta, DRPM_TAG_TGTSIZE, &tgt_size));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ulong(delta, DRPM_TAG_TGTHEADERLEN, &tgt_header_len));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ullong(delta, DRPM_TAG_EXTDATALEN, &ext_data_len));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ullong(delta, DRPM_TAG_INTDATALEN, &int_data_len));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_FILENAME, &drpms->filenames[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_SEQUENCE, &drpms->sequences[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_SRCNEVR, &drpms->src_nevrs[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_TGTNEVR, &drpms->tgt_nevrs[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_TGTMD5, &drpms->tgt_md5s[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_TGTLEAD, &drpms->tgt_leads[index]));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ulong_array(delta, DRPM_TAG_INTCOPIES, &drpms->int_copies_arrays[index], &int_copies_size));
    assert_int_equal(DRPM_ERR_OK, drpm_get_ulong_array(delta, DRPM_TAG_EXTCOPIES, &drpms->ext_copies_arrays[index], &ext_copies_size));
    filename = drpms->filenames[index];
    sequence = drpms->sequences[index];
    src_nevr = drpms->src_nevrs[index];
    tgt_nevr = drpms->tgt_nevrs[index];
    tgt_md5 = drpms->tgt_md5s[index];
    tgt_lead = drpms->tgt_leads[index];
    int_copies = drpms->int_copies_arrays[index];
    ext_copies = drpms->ext_copies_arrays[index];

    assert_non_null(filename);
    assert_non_null(sequence);
    assert_non_null(src_nevr);
    assert_non_null(tgt_nevr);
    assert_non_null(tgt_md5);
    assert_non_null(tgt_lead);

    assert_string_equal(delta_name, filename);
    assert_int_equal(DRPM_TYPE_STANDARD, type);
    assert_int_equal(3, version);
    assert_int_equal(DRPM_COMP_LZIP, comp);
    assert_not_in_range(strlen(sequence), 0, (MD5_DIGEST_LENGTH * 2) - 1);
    assert_int_equal(filesize(NEWRPM_2), tgt_size);
    assert_int_equal(MD5_DIGEST_LENGTH * 2, strlen(tgt_md5));
    assert_int_equal(0, tgt_header_len);
    assert_not_in_range(strlen(tgt_lead), 0, (96 + 16) - 1);
    assert_true(int_copies_size % 2 == 0);
    assert_true(ext_copies_size % 2 == 0);

    unsigned long int_copies_count = int_copies_size / 2;
    unsigned long ext_copies_count = ext_copies_size / 2;
    unsigned long count;
    unsigned long long off;

    count = 0;
    off = 0;
    for (unsigned long i = 0; i < int_copies_count; i++) {
        count += int_copies[2 * i];
        assert_false(count > ext_copies_count);
        off += int_copies[2 * i + 1];
        assert_false(off > int_data_len);
    }

    off = 0;
    for (unsigned long i = 0; i < ext_copies_count; i++) {
        off += (int32_t)ext_copies[2 * i];
        assert_false(off > ext_data_len);
        off += ext_copies[2 * i + 1];
        assert_int_not_equal(0, off);
        assert_false(off > ext_data_len);
    }
}

/************************ drpm_check_sequence *************************/

static int check_setup(void **state)
{
    ssize_t line_len;
    FILE *file;
    char *sequence = NULL;
    size_t alloced = 0;

    if ((file = fopen(SEQFILE, "r")) == NULL)
        return -1;

    line_len = getline(&sequence, &alloced, file);
    fclose(file);

    if (line_len < 0)
        return -1;

    if (sequence[line_len] == '\n')
        sequence[line_len] = '\0';

    *state = sequence;

    return 0;
}

static int check_teardown(void **state)
{
    free(*state);
    return 0;
}

static void check_sequence(void **state)
{
    assert_int_equal(DRPM_ERR_OK, drpm_check_sequence(OLDRPM_1, (const char *)*state, DRPM_CHECK_NONE));
}

/***************************** drpm_apply *****************************/

static void apply_standard(void **state)
{
    (void)state;
    assert_int_equal(DRPM_ERR_OK, drpm_apply(OLDRPM_1, DELTARPM_STANDARD, RPMOUT_STANDARD));
}

static void apply_rpmonly_noaddblk(void **state)
{
    (void)state;
    assert_int_equal(DRPM_ERR_OK, drpm_apply(OLDRPM_2, DELTARPM_RPMONLY_NOADDBLK, RPMOUT_RPMONLY_NOADDBLK));
}

static void apply_standard_lzip(void **state)
{
    (void)state;
    assert_int_equal(DRPM_ERR_OK, drpm_apply(OLDRPM_2, DELTARPM_STANDARD_LZIP, RPMOUT_STANDARD_LZIP));
}

/***************************** run tests ******************************/

int main()
{
    int failed;
    const struct CMUnitTest make_tests[] = {
        cmocka_unit_test(make_nodiff),
        cmocka_unit_test(make_identity),
        cmocka_unit_test(make_rpmonly),
        cmocka_unit_test(make_standard),
        cmocka_unit_test(make_rpmonly_noaddblk),
        cmocka_unit_test(make_standard_lzip)
    };
    const struct CMUnitTest read_tests[DELTARPM_COUNT] = {
        cmocka_unit_test(read_nodiff),
        cmocka_unit_test(read_identity),
        cmocka_unit_test(read_rpmonly),
        cmocka_unit_test(read_standard),
        cmocka_unit_test(read_rpmonly_noaddblk),
        cmocka_unit_test(read_standard_lzip)
    };
    const struct CMUnitTest check_tests[] = {
        cmocka_unit_test(check_sequence)
    };
    const struct CMUnitTest apply_tests[] = {
        cmocka_unit_test(apply_standard),
        cmocka_unit_test(apply_rpmonly_noaddblk),
        cmocka_unit_test(apply_standard_lzip)
    };

    failed = cmocka_run_group_tests_name("drpm_make()", make_tests, make_setup, make_teardown);
    if (failed)
        return failed;

    failed = cmocka_run_group_tests_name("drpm_read()", read_tests, read_setup, read_teardown);
    if (failed)
        return failed;

    failed = cmocka_run_group_tests_name("drpm_check_sequence()", check_tests, check_setup, check_teardown);
    if (failed)
        return failed;

    failed = cmocka_run_group_tests_name("drpm_apply()", apply_tests, NULL, NULL);
    if (failed)
        return failed;

    return 0;
}
