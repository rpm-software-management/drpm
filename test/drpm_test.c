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

#include "../src/drpm.h"
#include "../src/drpm_private.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#define DELTAS 2
#define MOCK_TESTS 21

#define UINT_UNSUP_TAGS 14
#define ULONG_UNSUP_TAGS 12
#define ULLONG_UNSUP_TAGS 10
#define STRING_UNSUP_TAGS 12
#define ULONG_ARR_UNSUP_TAGS 16

int __real_read_be32(int, uint32_t *);
int __real_readdelta_rpmonly(int, drpm *);
int __real_readdelta_standard(int, drpm *);
int __real_readdelta_rest(int, drpm *);
int __real_compstrm_init(struct compstrm **, int, uint32_t *);
int __real_compstrm_read_be32(struct compstrm *, uint32_t *);
int __real_compstrm_read(struct compstrm *, size_t, char *);
int __real_compstrm_destroy(struct compstrm **);

struct delta_meta {
    drpm *delta;
    uint16_t version;
    uint16_t type;
    uint16_t comp;
    uint16_t tgt_comp;
    uint32_t tgt_size;
    uint32_t tgt_header_len;
    uint32_t payload_fmt_off;
};

struct delta_meta deltas[DELTAS];
drpm *delta;
char **files;
int test_no;

LargestIntegralType types[] = {
    DRPM_TYPE_STANDARD,
    DRPM_TYPE_RPMONLY
};
LargestIntegralType comps[] = {
    DRPM_COMP_NONE,
    DRPM_COMP_GZIP,
    DRPM_COMP_BZIP2,
    DRPM_COMP_LZMA,
    DRPM_COMP_XZ,
    DRPM_COMP_LZIP
};

void print_help()
{
    printf("Usage: ./drpm_test ARG1 ARG2 ARG3 ARG4 ARG5\n"
           "Runs unit tests for the drpm package.\n\n"
           "Arguments are paths to files that have the following qualities.\n"
           "  ARG1   Valid deltarpm file, standard (V1, bzip2 compression).\n"
           "  ARG2   Valid deltarpm file, rpm-only (V3, xz compression).\n"
           "  ARG3   A valid rpm file, but not a deltarpm.\n"
           "  ARG4   A file that is neither an rpm nor a deltarpm.\n"
           "  ARG5   A file name that does not exist.\n");
}

int __wrap_read_be32(int filedesc, uint32_t *buffer_ret)
{
    switch (test_no) {
    case 1:
    case 2:
        return (int)mock();
    default:
        return __real_read_be32(filedesc, buffer_ret);
    }
}

int __wrap_readdelta_rpmonly(int filedesc, drpm *delta)
{
    switch (test_no) {
    case 3:
    case 4:
    case 5:
        return (int)mock();
    default:
        return __real_readdelta_rpmonly(filedesc, delta);
    }
}

int __wrap_readdelta_standard(int filedesc, drpm *delta)
{
    switch (test_no) {
    case 6:
    case 7:
    case 8:
        return (int)mock();
    default:
        return __real_readdelta_standard(filedesc, delta);
    }
}

int __wrap_readdelta_rest(int filedesc, drpm *delta)
{
    switch (test_no) {
    case 9:
    case 10:
        return (int)mock();
    default:
        return __real_readdelta_rest(filedesc, delta);
    }
}

int __wrap_compstrm_init(struct compstrm **strm, int filedesc, uint32_t *comp)
{
    switch (test_no) {
    case 11:
    case 12:
    case 13:
    case 14:
    case 15:
        return (int)mock();
    default:
        return __real_compstrm_init(strm, filedesc, comp);
    }
}

int __wrap_compstrm_read_be32(struct compstrm *strm, uint32_t *buffer_ret)
{
    switch (test_no) {
    case 16:
        return (int)mock();
    default:
        return __real_compstrm_read_be32(strm, buffer_ret);
    }
}

int __wrap_compstrm_read(struct compstrm *strm, size_t read_len, char *buffer_ret)
{
    switch (test_no) {
    case 17:
    case 18:
    case 19:
    case 20:
        return (int)mock();
    default:
        return __real_compstrm_read(strm, read_len, buffer_ret);
    }
}

int __wrap_compstrm_destroy(struct compstrm **strm)
{
    switch (test_no) {
    case 21:
        __real_compstrm_destroy(strm);
        return (int)mock();
    default:
        return __real_compstrm_destroy(strm);
    }
}

static void test_drpm_read_err_mock(void **state)
{
    (void) state; /* unused */

    char *delta_file;
    LargestIntegralType ret_vals[MOCK_TESTS] = {
        DRPM_ERR_IO,
        DRPM_ERR_FORMAT,
        DRPM_ERR_FORMAT,
        DRPM_ERR_MEMORY,
        DRPM_ERR_IO,
        DRPM_ERR_IO,
        DRPM_ERR_FORMAT,
        DRPM_ERR_MEMORY,
        DRPM_ERR_FORMAT,
        DRPM_ERR_MEMORY,
        DRPM_ERR_ARGS,
        DRPM_ERR_IO,
        DRPM_ERR_MEMORY,
        DRPM_ERR_CONFIG,
        DRPM_ERR_FORMAT,
        DRPM_ERR_ARGS,
        DRPM_ERR_ARGS,
        DRPM_ERR_IO,
        DRPM_ERR_FORMAT,
        DRPM_ERR_MEMORY,
        DRPM_ERR_ARGS
    };

    for (test_no = 1; test_no <= MOCK_TESTS; test_no++) {

        switch (test_no) {
        case 1:
        case 2:
            will_return(__wrap_read_be32, ret_vals[test_no-1]);
            break;
        case 3:
        case 4:
        case 5:
            will_return(__wrap_readdelta_rpmonly, ret_vals[test_no-1]);
            break;
        case 6:
        case 7:
        case 8:
            will_return(__wrap_readdelta_standard, ret_vals[test_no-1]);
            break;
        case 9:
        case 10:
            will_return(__wrap_readdelta_rest, ret_vals[test_no-1]);
            break;
        case 11:
        case 12:
        case 13:
        case 14:
        case 15:
            will_return(__wrap_compstrm_init, ret_vals[test_no-1]);
            break;
        case 16:
            will_return(__wrap_compstrm_read_be32, ret_vals[test_no-1]);
            break;
        case 17:
        case 18:
        case 19:
        case 20:
            will_return(__wrap_compstrm_read, ret_vals[test_no-1]);
            break;
        case 21:
            will_return(__wrap_compstrm_destroy, ret_vals[test_no-1]);
            break;
        }

        switch (test_no) {
        case 3:
        case 4:
        case 5:
            delta_file = files[1];
            break;
        default:
            delta_file = files[0];
            break;
        }

        assert_int_equal(ret_vals[test_no-1], drpm_read(&delta, delta_file));
    }
}

static void test_drpm_read_err_input(void **state)
{
    (void) state; /* unused */
    test_no = 0;

    assert_int_equal(DRPM_ERR_ARGS, drpm_read(&delta, NULL));
    assert_int_equal(DRPM_ERR_ARGS, drpm_read(NULL, files[1]));

    assert_int_equal(DRPM_ERR_IO, drpm_read(&delta, files[4]));

    assert_int_equal(DRPM_ERR_FORMAT, drpm_read(&delta, files[2]));
    assert_int_equal(DRPM_ERR_FORMAT, drpm_read(&delta, files[3]));
}

static void test_drpm_read_ok(void **state)
{
    (void) state; /* unused */
    test_no = 0;

    for (int i = 0; i < DELTAS; i++) {
        assert_int_equal(DRPM_ERR_OK, drpm_read(&deltas[i].delta, files[i]));
    }
}

static void test_drpm_get_uint(void **state)
{
    (void) state; /* unused */
    test_no = 0;

    unsigned version;
    unsigned type;
    unsigned comp;
    unsigned tgt_size;
    unsigned tgt_comp;

    unsigned tmp = UINT_MAX;
    int unsup_tags[UINT_UNSUP_TAGS] = {
        DRPM_TAG_FILENAME,
        DRPM_TAG_SEQUENCE,
        DRPM_TAG_SRCNEVR,
        DRPM_TAG_TGTNEVR,
        DRPM_TAG_TGTMD5,
        DRPM_TAG_TGTCOMPPARAM,
        DRPM_TAG_TGTHEADERLEN,
        DRPM_TAG_ADJELEMS,
        DRPM_TAG_TGTLEAD,
        DRPM_TAG_PAYLOADFMTOFF,
        DRPM_TAG_INTCOPIES,
        DRPM_TAG_EXTCOPIES,
        DRPM_TAG_EXTDATALEN,
        DRPM_TAG_INTDATALEN
    };

    for (int i = 0; i < DELTAS; i++) {
        assert_int_equal(DRPM_ERR_OK, drpm_get_uint(deltas[i].delta, DRPM_TAG_VERSION, (unsigned *)&deltas[i].version));
        assert_int_equal(DRPM_ERR_OK, drpm_get_uint(deltas[i].delta, DRPM_TAG_TYPE, (unsigned *)&deltas[i].type));
        assert_int_equal(DRPM_ERR_OK, drpm_get_uint(deltas[i].delta, DRPM_TAG_COMP, (unsigned *)&deltas[i].comp));
        assert_int_equal(DRPM_ERR_OK, drpm_get_uint(deltas[i].delta, DRPM_TAG_TGTSIZE, &tgt_size));
        assert_int_equal(DRPM_ERR_OK, drpm_get_uint(deltas[i].delta, DRPM_TAG_TGTCOMP, (unsigned *)&deltas[i].tgt_comp));

        version = (unsigned)deltas[i].version;
        type = (unsigned)deltas[i].type;
        comp = (unsigned)deltas[i].comp;
        tgt_comp = (unsigned)deltas[i].tgt_comp;

        assert_in_range(version, 1, 3);
        assert_in_set(type, types, 2);
        assert_in_set(comp, comps, 6);
        assert_in_set(tgt_comp, comps, 6);
        if (version < 2)
            assert_int_equal(0, tgt_size);
    }

    assert_int_equal(DRPM_ERR_ARGS, drpm_get_uint(NULL, DRPM_TAG_VERSION, &tmp));
    assert_int_equal(DRPM_ERR_ARGS, drpm_get_uint(delta, DRPM_TAG_COMP, NULL));

    for (int i = 0; i < UINT_UNSUP_TAGS; i++) {
        assert_int_equal(DRPM_ERR_ARGS, drpm_get_uint(delta, unsup_tags[i], &tmp));
        assert_int_equal(UINT_MAX, tmp);
    }
}

static void test_drpm_get_ulong(void **state)
{
    (void) state; /* unused */
    test_no = 0;

    unsigned long version;
    unsigned long type;
    unsigned long comp;
    unsigned long tgt_size;
    unsigned long tgt_comp;
    unsigned long tgt_header_len;
    unsigned long payload_fmt_off;

    unsigned long tmp = ULONG_MAX;
    int unsup_tags[ULONG_UNSUP_TAGS] = {
        DRPM_TAG_FILENAME,
        DRPM_TAG_SEQUENCE,
        DRPM_TAG_SRCNEVR,
        DRPM_TAG_TGTNEVR,
        DRPM_TAG_TGTMD5,
        DRPM_TAG_TGTCOMPPARAM,
        DRPM_TAG_ADJELEMS,
        DRPM_TAG_TGTLEAD,
        DRPM_TAG_INTCOPIES,
        DRPM_TAG_EXTCOPIES,
        DRPM_TAG_EXTDATALEN,
        DRPM_TAG_INTDATALEN
    };

    for (int i = 0; i < DELTAS; i++) {
        assert_int_equal(DRPM_ERR_OK, drpm_get_ulong(deltas[i].delta, DRPM_TAG_VERSION, &version));
        assert_int_equal(DRPM_ERR_OK, drpm_get_ulong(deltas[i].delta, DRPM_TAG_TYPE, &type));
        assert_int_equal(DRPM_ERR_OK, drpm_get_ulong(deltas[i].delta, DRPM_TAG_COMP, &comp));
        assert_int_equal(DRPM_ERR_OK, drpm_get_ulong(deltas[i].delta, DRPM_TAG_TGTSIZE, (unsigned long *)&deltas[i].tgt_size));
        assert_int_equal(DRPM_ERR_OK, drpm_get_ulong(deltas[i].delta, DRPM_TAG_TGTCOMP, &tgt_comp));
        assert_int_equal(DRPM_ERR_OK, drpm_get_ulong(deltas[i].delta, DRPM_TAG_TGTHEADERLEN, (unsigned long *)&deltas[i].tgt_header_len));
        assert_int_equal(DRPM_ERR_OK, drpm_get_ulong(deltas[i].delta, DRPM_TAG_PAYLOADFMTOFF, (unsigned long *)&deltas[i].payload_fmt_off));

        tgt_size = (unsigned long)deltas[i].tgt_size;
        tgt_header_len = (unsigned long)deltas[i].tgt_header_len;
        payload_fmt_off = (unsigned long)deltas[i].payload_fmt_off;

        assert_in_range(version, 1, 3);
        assert_in_set(type, types, 2);
        assert_in_set(comp, comps, 6);
        assert_in_set(tgt_comp, comps, 6);
        if (version < 2)
            assert_int_equal(0, tgt_size);
        if (type == DRPM_TYPE_RPMONLY)
            assert_int_not_equal(0, tgt_header_len);

        assert_int_equal(version, deltas[i].version);
        assert_int_equal(type, deltas[i].type);
        assert_int_equal(comp, deltas[i].comp);
        assert_int_equal(tgt_comp, deltas[i].tgt_comp);
    }

    assert_int_equal(DRPM_ERR_ARGS, drpm_get_ulong(NULL, DRPM_TAG_PAYLOADFMTOFF, &payload_fmt_off));
    assert_int_equal(DRPM_ERR_ARGS, drpm_get_ulong(delta, DRPM_TAG_TGTSIZE, NULL));

    for (int i = 0; i < ULONG_UNSUP_TAGS; i++) {
        assert_int_equal(DRPM_ERR_ARGS, drpm_get_ulong(delta, unsup_tags[i], &tmp));
        assert_int_equal(ULONG_MAX, tmp);
    }
}

static void test_drpm_get_ullong(void **state)
{
    (void) state; /* unused */
    test_no = 0;

    unsigned long long version;
    unsigned long long type;
    unsigned long long comp;
    unsigned long long tgt_size;
    unsigned long long tgt_comp;
    unsigned long long tgt_header_len;
    unsigned long long payload_fmt_off;
    unsigned long long ext_data_len;
    unsigned long long int_data_len;

    unsigned long long tmp = ULLONG_MAX;
    int unsup_tags[ULLONG_UNSUP_TAGS] = {
        DRPM_TAG_FILENAME,
        DRPM_TAG_SEQUENCE,
        DRPM_TAG_SRCNEVR,
        DRPM_TAG_TGTNEVR,
        DRPM_TAG_TGTMD5,
        DRPM_TAG_TGTCOMPPARAM,
        DRPM_TAG_ADJELEMS,
        DRPM_TAG_TGTLEAD,
        DRPM_TAG_INTCOPIES,
        DRPM_TAG_EXTCOPIES,
    };

    for (int i = 0; i < DELTAS; i++) {
        assert_int_equal(DRPM_ERR_OK, drpm_get_ullong(deltas[i].delta, DRPM_TAG_VERSION, &version));
        assert_int_equal(DRPM_ERR_OK, drpm_get_ullong(deltas[i].delta, DRPM_TAG_TYPE, &type));
        assert_int_equal(DRPM_ERR_OK, drpm_get_ullong(deltas[i].delta, DRPM_TAG_COMP, &comp));
        assert_int_equal(DRPM_ERR_OK, drpm_get_ullong(deltas[i].delta, DRPM_TAG_TGTSIZE, &tgt_size));
        assert_int_equal(DRPM_ERR_OK, drpm_get_ullong(deltas[i].delta, DRPM_TAG_TGTCOMP, &tgt_comp));
        assert_int_equal(DRPM_ERR_OK, drpm_get_ullong(deltas[i].delta, DRPM_TAG_TGTHEADERLEN, &tgt_header_len));
        assert_int_equal(DRPM_ERR_OK, drpm_get_ullong(deltas[i].delta, DRPM_TAG_PAYLOADFMTOFF, &payload_fmt_off));
        assert_int_equal(DRPM_ERR_OK, drpm_get_ullong(deltas[i].delta, DRPM_TAG_EXTDATALEN, &ext_data_len));
        assert_int_equal(DRPM_ERR_OK, drpm_get_ullong(deltas[i].delta, DRPM_TAG_INTDATALEN, &int_data_len));

        assert_in_range(version, 1, 3);
        assert_in_set(type, types, 2);
        assert_in_set(comp, comps, 6);
        assert_in_set(tgt_comp, comps, 6);
        if (version < 2)
            assert_int_equal(0, tgt_size);
        if (type == DRPM_TYPE_RPMONLY)
            assert_int_not_equal(0, tgt_header_len);

        assert_int_equal(version, deltas[i].version);
        assert_int_equal(type, deltas[i].type);
        assert_int_equal(comp, deltas[i].comp);
        assert_int_equal(tgt_comp, deltas[i].tgt_comp);
        assert_int_equal(tgt_size, deltas[i].tgt_size);
        assert_int_equal(tgt_header_len, deltas[i].tgt_header_len);
        assert_int_equal(payload_fmt_off, deltas[i].payload_fmt_off);
    }

    assert_int_equal(DRPM_ERR_ARGS, drpm_get_ullong(NULL, DRPM_TAG_TYPE, &type));
    assert_int_equal(DRPM_ERR_ARGS, drpm_get_ullong(delta, DRPM_TAG_INTDATALEN, NULL));

    for (int i = 0; i < ULLONG_UNSUP_TAGS; i++) {
        assert_int_equal(DRPM_ERR_ARGS, drpm_get_ullong(delta, unsup_tags[i], &tmp));
        assert_int_equal(ULLONG_MAX, tmp);
    }
}

static void test_drpm_get_string(void **state)
{
    (void) state; /* unused */
    test_no = 0;

    char *filename;
    char *sequence;
    char *src_nevr;
    char *tgt_nevr;
    char *tgt_md5;
    char *tgt_comp_param;
    char *tgt_lead;

    char *tmp = NULL;
    int unsup_tags[STRING_UNSUP_TAGS] = {
        DRPM_TAG_VERSION,
        DRPM_TAG_TYPE,
        DRPM_TAG_COMP,
        DRPM_TAG_TGTSIZE,
        DRPM_TAG_TGTCOMP,
        DRPM_TAG_TGTHEADERLEN,
        DRPM_TAG_ADJELEMS,
        DRPM_TAG_PAYLOADFMTOFF,
        DRPM_TAG_INTCOPIES,
        DRPM_TAG_EXTCOPIES,
        DRPM_TAG_EXTDATALEN,
        DRPM_TAG_INTDATALEN
    };

    for (int i = 0; i < DELTAS; i++) {
        assert_int_equal(DRPM_ERR_OK, drpm_get_string(deltas[i].delta, DRPM_TAG_FILENAME, &filename));
        assert_int_equal(DRPM_ERR_OK, drpm_get_string(deltas[i].delta, DRPM_TAG_SEQUENCE, &sequence));
        assert_int_equal(DRPM_ERR_OK, drpm_get_string(deltas[i].delta, DRPM_TAG_SRCNEVR, &src_nevr));
        assert_int_equal(DRPM_ERR_OK, drpm_get_string(deltas[i].delta, DRPM_TAG_TGTNEVR, &tgt_nevr));
        assert_int_equal(DRPM_ERR_OK, drpm_get_string(deltas[i].delta, DRPM_TAG_TGTMD5, &tgt_md5));
        assert_int_equal(DRPM_ERR_OK, drpm_get_string(deltas[i].delta, DRPM_TAG_TGTCOMPPARAM, &tgt_comp_param));
        assert_int_equal(DRPM_ERR_OK, drpm_get_string(deltas[i].delta, DRPM_TAG_TGTLEAD, &tgt_lead));

        assert_string_equal(files[i], filename);
        assert_true(16*2 <= strlen(sequence));
        assert_int_equal(16*2, strlen(tgt_md5));
        if (deltas[i].version < 2)
            assert_null(tgt_comp_param);
        if (deltas[i].type == DRPM_TYPE_RPMONLY)
            assert_int_equal(16*2, strlen(sequence));

        free(filename);
        free(sequence);
        free(src_nevr);
        free(tgt_nevr);
        free(tgt_md5);
        free(tgt_comp_param);
        free(tgt_lead);
    }

    assert_int_equal(DRPM_ERR_ARGS, drpm_get_string(NULL, DRPM_TAG_FILENAME, &filename));
    assert_int_equal(DRPM_ERR_ARGS, drpm_get_string(delta, DRPM_TAG_SEQUENCE, NULL));

    for (int i = 0; i < STRING_UNSUP_TAGS; i++) {
        assert_int_equal(DRPM_ERR_ARGS, drpm_get_string(delta, unsup_tags[i], &tmp));
        assert_null(tmp);
    }
}

static void test_drpm_get_ulong_array(void **state)
{
    (void) state; /* unused */
    test_no = 0;

    unsigned long *adj_elems;
    unsigned long *int_copies;
    unsigned long *ext_copies;
    unsigned long adj_elems_size;
    unsigned long int_copies_size;
    unsigned long ext_copies_size;

    unsigned long *tmp_array = NULL;
    unsigned long tmp_size = ULONG_MAX;
    int unsup_tags[ULONG_ARR_UNSUP_TAGS] = {
        DRPM_TAG_FILENAME,
        DRPM_TAG_VERSION,
        DRPM_TAG_TYPE,
        DRPM_TAG_SEQUENCE,
        DRPM_TAG_SRCNEVR,
        DRPM_TAG_TGTNEVR,
        DRPM_TAG_TGTSIZE,
        DRPM_TAG_TGTMD5,
        DRPM_TAG_TGTCOMP,
        DRPM_TAG_TGTCOMPPARAM,
        DRPM_TAG_TGTHEADERLEN,
        DRPM_TAG_TGTLEAD,
        DRPM_TAG_PAYLOADFMTOFF,
        DRPM_TAG_EXTDATALEN,
        DRPM_TAG_INTDATALEN
    };

    for (int i = 0; i < DELTAS; i++) {
        assert_int_equal(DRPM_ERR_OK, drpm_get_ulong_array(deltas[i].delta, DRPM_TAG_ADJELEMS, &adj_elems, &adj_elems_size));
        assert_int_equal(DRPM_ERR_OK, drpm_get_ulong_array(deltas[i].delta, DRPM_TAG_INTCOPIES, &int_copies, &int_copies_size));
        assert_int_equal(DRPM_ERR_OK, drpm_get_ulong_array(deltas[i].delta, DRPM_TAG_EXTCOPIES, &ext_copies, &ext_copies_size));

        assert_true(adj_elems_size % 2 == 0);
        assert_true(int_copies_size % 2 == 0);
        assert_true(ext_copies_size % 2 == 0);
        if (deltas[i].version < 3) {
            assert_null(adj_elems);
            assert_int_equal(0, adj_elems_size);
        }

        free(adj_elems);
        free(int_copies);
        free(ext_copies);
    }

    assert_int_equal(DRPM_ERR_ARGS, drpm_get_ulong_array(NULL, DRPM_TAG_ADJELEMS, &adj_elems, &adj_elems_size));
    assert_int_equal(DRPM_ERR_ARGS, drpm_get_ulong_array(delta, DRPM_TAG_INTCOPIES, NULL, &int_copies_size));
    assert_int_equal(DRPM_ERR_ARGS, drpm_get_ulong_array(delta, DRPM_TAG_EXTCOPIES, &ext_copies, NULL));

    for (int i = 0; i < ULONG_ARR_UNSUP_TAGS; i++) {
        assert_int_equal(DRPM_ERR_ARGS, drpm_get_ulong_array(delta, unsup_tags[i], &tmp_array, &tmp_size));
        assert_null(tmp_array);
        assert_int_equal(ULONG_MAX, tmp_size);
    }
}

static void test_drpm_destroy_err(void **state)
{
    (void) state; /* unused */
    test_no = 0;

    drpm *null_delta = NULL;

    assert_int_equal(DRPM_ERR_ARGS, drpm_destroy(NULL));
    assert_int_equal(DRPM_ERR_ARGS, drpm_destroy(&null_delta));
}

static void test_drpm_destroy_ok(void **state)
{
    (void) state; /* unused */
    test_no = 0;

    for (int i = 0; i < DELTAS; i++) {
        assert_int_equal(DRPM_ERR_OK, drpm_destroy(&deltas[i].delta));
    }
}

int main(int argc, char **argv)
{
    if (argc != 6) {
        print_help();
        return 1;
    }

    files = argv + 1;
    delta = deltas[0].delta;

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_drpm_read_err_mock),
        cmocka_unit_test(test_drpm_read_err_input),
        cmocka_unit_test(test_drpm_read_ok),
        cmocka_unit_test(test_drpm_get_uint),
        cmocka_unit_test(test_drpm_get_ulong),
        cmocka_unit_test(test_drpm_get_ullong),
        cmocka_unit_test(test_drpm_get_string),
        cmocka_unit_test(test_drpm_get_ulong_array),
        cmocka_unit_test(test_drpm_destroy_err),
        cmocka_unit_test(test_drpm_destroy_ok)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
