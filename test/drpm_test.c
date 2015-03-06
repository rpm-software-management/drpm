#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "../src/drpm.h"

drpm *delta = NULL;
char **files;

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

static void test_drpm_read(void **state)
{
    (void) state; /* unused */

    assert_int_equal(DRPM_ERR_ARGS, drpm_read(&delta, NULL));
    assert_int_equal(DRPM_ERR_ARGS, drpm_read(NULL, files[1]));

    assert_int_equal(DRPM_ERR_IO, drpm_read(&delta, files[4]));

    assert_int_equal(DRPM_ERR_FORMAT, drpm_read(&delta, files[2]));
    assert_int_equal(DRPM_ERR_FORMAT, drpm_read(&delta, files[3]));

    assert_int_equal(DRPM_ERR_OK, drpm_read(&delta, files[0]));
}

static void test_drpm_get_uint(void **state)
{
    (void) state; /* unused */

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

static void test_drpm_destroy(void **state)
{
    (void) state; /* unused */

    drpm *null_delta = NULL;

    assert_int_equal(DRPM_ERR_ARGS, drpm_destroy(NULL));
    assert_int_equal(DRPM_ERR_ARGS, drpm_destroy(&null_delta));

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
        cmocka_unit_test(test_drpm_read),
        cmocka_unit_test(test_drpm_get_uint),
        cmocka_unit_test(test_drpm_get_string),
        cmocka_unit_test(test_drpm_destroy)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
