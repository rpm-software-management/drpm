cmake_minimum_required(VERSION 2.8.5)

project(drpm C)

set(DRPM_MAJOR_VERSION 0)
set(DRPM_MINOR_VERSION 3)
set(DRPM_PATCH_VERSION 0)
set(DRPM_VERSION ${DRPM_MAJOR_VERSION}.${DRPM_MINOR_VERSION}.${DRPM_PATCH_VERSION})

include(GNUInstallDirs)

option(ENABLE_TESTS "Build and run tests?" ON)
option(WITH_ZSTD "Build with zstd support" ON)

find_package(PkgConfig REQUIRED)

find_package(ZLIB REQUIRED)
find_package(BZip2 REQUIRED)
find_package(LibLZMA REQUIRED)

pkg_check_modules(RPM rpm REQUIRED)
pkg_check_modules(LIBCRYPTO libcrypto REQUIRED)
if(WITH_ZSTD)
   pkg_check_modules(ZSTD REQUIRED libzstd)
endif()

add_custom_target(dist COMMAND ${CMAKE_MAKE_PROGRAM} package_source)
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure)

set(CPACK_PACKAGE_NAME ${CMAKE_PROJECT_NAME})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "A small library for fetching information from deltarpm packages")
set(CPACK_PACKAGE_CONTACT "Matej Chalk <mchalk@redhat.com>")
set(CPACK_PACKAGE_VERSION_MAJOR ${DRPM_MAJOR_VERSION})
set(CPACK_PACKAGE_VERSION_MINOR ${DRPM_MINOR_VERSION})
set(CPACK_PACKAGE_VERSION_PATCH ${DRPM_PATCH_VERSION})
set(CPACK_SOURCE_IGNORE_FILES "/tmp/" "/build/" "/pkg/" "/html/" "/latex/" "drpm.spec" "\\\\.git" ".*~" ".*\\\\.o")
set(CPACK_SOURCE_GENERATOR "TBZ2")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")

include(CPack)

set(DRPM_SOURCES drpm.c drpm_apply.c drpm_block.c drpm_compstrm.c drpm_decompstrm.c drpm_deltarpm.c drpm_diff.c drpm_make.c drpm_options.c drpm_read.c drpm_rpm.c drpm_search.c drpm_utils.c drpm_write.c)
set(DRPM_LINK_LIBRARIES ${ZLIB_LIBRARIES} ${BZIP2_LIBRARIES} ${LIBLZMA_LIBRARIES} ${RPM_LIBRARIES} ${LIBCRYPTO_LIBRARIES})

if(HAVE_LZLIB_DEVEL)
   list(APPEND DRPM_LINK_LIBRARIES lz)
endif()

if(WITH_ZSTD)
   list(APPEND DRPM_LINK_LIBRARIES ${ZSTD_LIBRARIES})
endif()

add_subdirectory(src)
add_subdirectory(doc)

if(ENABLE_TESTS)
   pkg_check_modules(CMOCKA cmocka REQUIRED)
   enable_testing()
   add_subdirectory(test)
endif()

configure_file(drpm.pc.in ${CMAKE_CURRENT_BINARY_DIR}/drpm.pc @ONLY)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/drpm.pc DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR}/pkgconfig)
