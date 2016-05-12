set(DRPM_TEST_SOURCES drpm_api_tests.c)
foreach(sourcefile ${DRPM_SOURCES})
   list(APPEND DRPM_TEST_SOURCES "../src/${sourcefile}")
endforeach()

set(DRPM_TEST_FILES refdrpm-copy.sha256 refseqfile-copy.txt)
set(DRPM_TEST_RPM_PACKAGE_NAMES drpm cmocka)
foreach(name ${DRPM_TEST_RPM_PACKAGE_NAMES})
   list(APPEND DRPM_TEST_FILES "${name}-old.rpm" "${name}-new.rpm")
endforeach()

set(DRPM_TEST_ARGS_CMP_FILES -d ${CMAKE_CURRENT_BINARY_DIR})
set(DRPM_TEST_ARGS_VALGRIND --error-exitcode=1 --read-var-info=yes --leak-check=full --show-leak-kinds=all --track-origins=yes --suppressions=${CMAKE_CURRENT_SOURCE_DIR}/lzma.supp)

set(CMAKE_BUILD_TYPE RelWithDebInfo)

file(
   COPY ${DRPM_TEST_FILES}
   DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
)

find_program(BASH_PROGRAM bash)
find_program(MAKEDELTARPM_PROGRAM makedeltarpm)
find_program(VALGRIND_PROGRAM valgrind)

if (NOT MAKEDELTARPM_PROGRAM)
   list(APPEND DRPM_TEST_ARGS_CMP_FILES -s)
endif()
if (HAVE_LZLIB_DEVEL)
   list(APPEND DRPM_TEST_ARGS_CMP_FILES -l)
endif()

add_executable(drpm_api_tests ${DRPM_TEST_SOURCES})

set_source_files_properties(${DRPM_TEST_SOURCES} PROPERTIES
   COMPILE_FLAGS "-std=c99 -pedantic -Wall -Wextra -DHAVE_CONFIG_H -I${CMAKE_BINARY_DIR}"
)

target_link_libraries(drpm_api_tests ${DRPM_LINK_LIBRARIES} ${CMOCKA_LIBRARIES})

add_test(
   NAME drpm_api_tests
   WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
   COMMAND ./drpm_api_tests
)

if (BASH_PROGRAM)
   add_test(
      NAME drpm_cmp_files
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      COMMAND ${BASH_PROGRAM} ${CMAKE_CURRENT_SOURCE_DIR}/drpm_cmp_files.sh ${DRPM_TEST_ARGS_CMP_FILES}
   )
   set_tests_properties(drpm_cmp_files PROPERTIES DEPENDS drpm_api_tests)
endif()


if (VALGRIND_PROGRAM)
   add_test(
      NAME drpm_memcheck
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      COMMAND valgrind ${DRPM_TEST_ARGS_VALGRIND} ./drpm_api_tests
   )
endif()

