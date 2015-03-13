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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "../src/drpm.h"
#include "../src/drpm_private.h"

int __real_read_be32(int, uint32_t *);
int __real_readdelta_standard(int, drpm *);
int __real_readdelta_rest(int, drpm *);
int __real_compstrm_init(struct compstrm **, int, uint32_t *);
int __real_compstrm_read_be32(struct compstrm *, uint32_t *);
int __real_compstrm_read(struct compstrm *, size_t, char *);

drpm *delta = NULL;
char **files;
int test_no = 0;

void print_help()
{
    printf("Usage: ./drpm_test ARG1 ARG2 ARG3 ARG4 ARG5\n"
           "Runs unit tests for the drpm package.\n\n"
           "Arguments are paths to files that have the following qualities.\n"
           "  ARG1   Valid deltarpm file, on which most tests will be conducted.\n"
           "  ARG2   Another valid deltarpm file.\n"
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

int __wrap_readdelta_standard(int filedesc, drpm *delta)
{
    switch (test_no) {
        case 3:
        case 4:
        case 5:
            return (int)mock();
        default:
            return __real_readdelta_standard(filedesc, delta);
    }
}

int __wrap_readdelta_rest(int filedesc, drpm *delta)
{
    switch (test_no) {
        case 6:
        case 7:
            return (int)mock();
        default:
            return __real_readdelta_rest(filedesc, delta);
    }
}

int __wrap_compstrm_init(struct compstrm **strm, int filedesc, uint32_t *comp)
{
    switch (test_no) {
        case 8:
        case 9:
        case 10:
        case 11:
        case 12:
            return (int)mock();
        default:
            return __real_compstrm_init(strm, filedesc, comp);
    }
}

int __wrap_compstrm_read_be32(struct compstrm *strm, uint32_t *buffer_ret)
{
    switch (test_no) {
        case 13:
            return (int)mock();
        default:
            return __real_compstrm_read_be32(strm, buffer_ret);
    }
}

int __wrap_compstrm_read(struct compstrm *strm, size_t read_len, char *buffer_ret)
{
    switch (test_no) {
        case 14:
        case 15:
        case 16:
        case 17:
            return (int)mock();
        default:
            return __real_compstrm_read(strm, read_len, buffer_ret);
    }
}

static void test_drpm_read_err_mock(void **state)
{
    (void) state; /* unused */

    LargestIntegralType ret_vals[17] = {
        DRPM_ERR_IO,
        DRPM_ERR_FORMAT,
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
        DRPM_ERR_MEMORY
    };

    for (test_no = 1; test_no <= 17; test_no++) {
        switch (test_no) {
            case 1:
            case 2:
                will_return(__wrap_read_be32, ret_vals[test_no-1]);
                break;
            case 3:
            case 4:
            case 5:
                will_return(__wrap_readdelta_standard, ret_vals[test_no-1]);
                break;
            case 6:
            case 7:
                will_return(__wrap_readdelta_rest, ret_vals[test_no-1]);
                break;
            case 8:
            case 9:
            case 10:
            case 11:
            case 12:
                will_return(__wrap_compstrm_init, ret_vals[test_no-1]);
                break;
            case 13:
                will_return(__wrap_compstrm_read_be32, ret_vals[test_no-1]);
                break;
            case 14:
            case 15:
            case 16:
            case 17:
                will_return(__wrap_compstrm_read, ret_vals[test_no-1]);
                break;
        }
        assert_int_equal(ret_vals[test_no-1], drpm_read(&delta, files[1]));
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

    assert_int_equal(DRPM_ERR_OK, drpm_read(&delta, files[0]));
}

static void test_drpm_get_uint(void **state)
{
    (void) state; /* unused */
    test_no = 0;

    unsigned version, type, comp, tgt_size;
    LargestIntegralType types[] = {
        DRPM_TYPE_STANDARD,
        DRPM_TYPE_RPMONLY
    };
    LargestIntegralType comps[] = {
        DRPM_COMP_NONE,
        DRPM_COMP_GZIP,
        DRPM_COMP_BZIP2,
        DRPM_COMP_LZMA,
        DRPM_COMP_XZ
    };

    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_VERSION, &version));
    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_TYPE, &type));
    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_COMP, &comp));
    assert_int_equal(DRPM_ERR_OK, drpm_get_uint(delta, DRPM_TAG_TGTSIZE, &tgt_size));

    assert_in_range(version, 1, 3);
    assert_in_set(type, types, 2);
    assert_in_set(comp, comps, 5);
    if (version < 2)
        assert_int_equal(0, tgt_size);

    assert_int_equal(DRPM_ERR_ARGS, drpm_get_uint(NULL, DRPM_TAG_VERSION, &version));
    assert_int_equal(DRPM_ERR_ARGS, drpm_get_uint(delta, DRPM_TAG_VERSION, NULL));
    assert_int_equal(DRPM_ERR_ARGS, drpm_get_uint(delta, DRPM_TAG_FILENAME, &version));
}

static void test_drpm_get_string(void **state)
{
    (void) state; /* unused */
    test_no = 0;

    char *filename, *sequence, *src_nevr, *tgt_nevr, *tgt_md5;

    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_FILENAME, &filename));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_SEQUENCE, &sequence));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_SRCNEVR, &src_nevr));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_TGTNEVR, &tgt_nevr));
    assert_int_equal(DRPM_ERR_OK, drpm_get_string(delta, DRPM_TAG_TGTMD5, &tgt_md5));

    assert_string_equal(files[0], filename);
    assert_true(strlen(sequence) >= 16*2);
    assert_true(strlen(tgt_md5) == 16*2);

    assert_int_equal(DRPM_ERR_ARGS, drpm_get_string(NULL, DRPM_TAG_FILENAME, &filename));
    assert_int_equal(DRPM_ERR_ARGS, drpm_get_string(delta, DRPM_TAG_FILENAME, NULL));
    assert_int_equal(DRPM_ERR_ARGS, drpm_get_string(delta, DRPM_TAG_VERSION, &filename));

    free(filename);
    free(sequence);
    free(src_nevr);
    free(tgt_nevr);
    free(tgt_md5);
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

    assert_int_equal(DRPM_ERR_OK, drpm_destroy(&delta));
}

int main(int argc, char **argv)
{
    if (argc != 6) {
        print_help();
        return 1;
    }

    files = argv + 1;

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_drpm_read_err_mock),
        cmocka_unit_test(test_drpm_read_err_input),
        cmocka_unit_test(test_drpm_read_ok),
        cmocka_unit_test(test_drpm_get_uint),
        cmocka_unit_test(test_drpm_get_string),
        cmocka_unit_test(test_drpm_destroy_err),
        cmocka_unit_test(test_drpm_destroy_ok)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
