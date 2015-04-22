include_directories(../src)

set(DRPM_TEST_SOURCES drpm_test.c ../src/drpm.c ../src/drpm_compstrm.c ../src/drpm_read.c ../src/drpm_utils.c)

if("${ARCH}" STREQUAL "x86_64")
   set(DRPM_TEST_STD_DELTA_FILE drpm_test_file_1.x86_64.drpm)
elseif("${ARCH}" STREQUAL "i386")
   set(DRPM_TEST_STD_DELTA_FILE drpm_test_file_1.i686.drpm)
elseif("${ARCH}" STREQUAL "armhfp")
   set(DRPM_TEST_STD_DELTA_FILE drpm_test_file_1.armv7hl.drpm)
else()
   set(DRPM_TEST_STD_DELTA_FILE drpm_test_file_1.noarch.drpm)
endif()

set(DRPM_TEST_FILES ${DRPM_TEST_STD_DELTA_FILE} drpm_test_file_2.drpm drpm_test_file_3.rpm drpm_test_file_4)
set(DRPM_TEST_ARGS ${DRPM_TEST_FILES} drpm_test_file_5)
set(DRPM_TEST_VALGRIND_ARGS --error-exitcode=1 --read-var-info=yes --leak-check=full --show-leak-kinds=all)

set(CMAKE_BUILD_TYPE RelWithDebInfo)

add_executable(drpm_test ${DRPM_TEST_SOURCES})

set_source_files_properties(${DRPM_TEST_SOURCES} PROPERTIES
   COMPILE_FLAGS "-std=c99 -pedantic -Wall -Wextra"
)

target_link_libraries(drpm_test z bz2 lzma rpm rpmio cmocka)

set_target_properties(drpm_test PROPERTIES
   LINK_FLAGS "-Wl,--wrap,read_be32 -Wl,--wrap,readdelta_rpmonly -Wl,--wrap,readdelta_standard -Wl,--wrap,readdelta_rest -Wl,--wrap,compstrm_init -Wl,--wrap,compstrm_read_be32 -Wl,--wrap,compstrm_read -Wl,--wrap,compstrm_destroy"
)

add_test(
   NAME drpm_test
   WORKING_DIRECTORY ${PROJECT_BINARY_DIR}/test
   COMMAND drpm_test ${DRPM_TEST_ARGS}
)

add_test(
   NAME drpm_test_valgrind
   WORKING_DIRECTORY ${PROJECT_BINARY_DIR}/test
   COMMAND valgrind ${DRPM_TEST_VALGRIND_ARGS} ./drpm_test ${DRPM_TEST_ARGS}
)

file(
   COPY ${DRPM_TEST_FILES}
   DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
)
