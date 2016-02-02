set(DRPM_TEST_SOURCES drpm_test.c ../src/drpm.c ../src/drpm_compstrm.c ../src/drpm_decompstrm.c ../src/drpm_deltarpm.c ../src/drpm_diff.c ../src/drpm_make.c ../src/drpm_read.c ../src/drpm_rpm.c ../src/drpm_search.c ../src/drpm_utils.c ../src/drpm_write.c)

set(DRPM_TEST_FILES drpm_test_file_1.drpm drpm_test_file_2.drpm drpm_test_file_3.rpm drpm_test_file_4)
set(DRPM_TEST_ARGS ${DRPM_TEST_FILES} drpm_test_file_5)
set(DRPM_TEST_VALGRIND_ARGS --error-exitcode=1 --read-var-info=yes --leak-check=full --show-leak-kinds=all)

set(CMAKE_BUILD_TYPE RelWithDebInfo)

find_program(DRPM_VALGRIND_PATH NAMES valgrind)

add_executable(drpm_test ${DRPM_TEST_SOURCES})

set_source_files_properties(${DRPM_TEST_SOURCES} PROPERTIES
   COMPILE_FLAGS "-std=c99 -pedantic -Wall -Wextra -DHAVE_CONFIG_H -I${CMAKE_BINARY_DIR}"
)

target_link_libraries(drpm_test ${ZLIB_LIBRARIES} ${BZIP2_LIBRARIES} ${LIBLZMA_LIBRARIES} ${RPM_LIBRARIES} ${LIBCRYPTO_LIBRARIES} ${CMOCKA_LIBRARIES})

set_target_properties(drpm_test PROPERTIES
   LINK_FLAGS "-Wl,--wrap,read_be32 -Wl,--wrap,readdelta_rpmonly -Wl,--wrap,readdelta_standard -Wl,--wrap,readdelta_rest -Wl,--wrap,decompstrm_init -Wl,--wrap,decompstrm_read_be32 -Wl,--wrap,decompstrm_read -Wl,--wrap,decompstrm_destroy"
)

add_test(
   NAME drpm_test
   WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
   COMMAND ./drpm_test ${DRPM_TEST_ARGS}
)

if (DRPM_VALGRIND_PATH)
   add_test(
      NAME drpm_test_valgrind
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      COMMAND valgrind ${DRPM_TEST_VALGRIND_ARGS} ./drpm_test ${DRPM_TEST_ARGS}
   )
endif()

file(
   COPY ${DRPM_TEST_FILES}
   DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
)
