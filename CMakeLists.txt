cmake_minimum_required(VERSION 2.8)

project(drpm)

add_custom_target(dist COMMAND ${CMAKE_MAKE_PROGRAM} package_source)

set(CPACK_PACKAGE_NAME ${CMAKE_PROJECT_NAME})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "A small library for fetching information from deltarpm packages")
set(CPACK_PACKAGE_CONTACT "Matej Chalk <mchalk@redhat.com>")
set(CPACK_PACKAGE_VERSION_MAJOR 0)
set(CPACK_PACKAGE_VERSION_MINOR 1)
set(CPACK_PACKAGE_VERSION_PATCH 3)
set(CPACK_SOURCE_IGNORE_FILES "/build/" "/test/" "/doc/" "/pkg/" "\\\\.git" ".*~" ".*\\\\.o")
set(CPACK_SOURCE_GENERATOR "TBZ2")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")

include(CPack)

set(DRPM_SOURCES drpm.c drpm_compstrm.c drpm_read.c drpm_utils.c)

set(DRPM_VERSION_MAJOR 0)
set(DRPM_VERSION_MINOR 0)
set(DRPM_VERSION_PATCH 1)

set(DRPM_VERSION ${DRPM_VERSION_MAJOR}.${DRPM_VERSION_MINOR}.${DRPM_VERSION_PATCH})
set(DRPM_SOVERSION ${DRPM_VERSION_MAJOR})

set(CMAKE_BUILD_TYPE RelWithDebInfo)

add_library(drpm SHARED ${DRPM_SOURCES})

set_source_files_properties(${DRPM_SOURCES} PROPERTIES
   COMPILE_FLAGS "-std=c99 -pedantic -Wall -Wextra"
)

set_target_properties(drpm PROPERTIES
   VERSION ${DRPM_VERSION}
   SOVERSION ${DRPM_SOVERSION}
   LINK_FLAGS "-lz -lbz2 -llzma -lrpm -lrpmio"
)

enable_testing()

add_subdirectory(test)
add_subdirectory(doc)

install(TARGETS drpm DESTINATION ${LIB_INSTALL_DIR})
install(FILES drpm.h DESTINATION ${INCLUDE_INSTALL_DIR})
install(FILES drpm.pc DESTINATION ${LIB_INSTALL_DIR}/pkgconfig)
