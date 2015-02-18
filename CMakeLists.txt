cmake_minimum_required(VERSION 2.8)

project(drpm)

set(SOURCES drpm.c drpm_compstrm.c drpm_read.c drpm_utils.c)

set(CMAKE_BUILD_TYPE RelWithDebInfo)

add_library(drpm SHARED ${SOURCES})

set_source_files_properties(${SOURCES} PROPERTIES
   COMPILE_FLAGS "-std=c99 -pedantic -Wall -Wextra"
)

set_target_properties(drpm PROPERTIES
   VERSION 0.0.1
   SOVERSION 0
   LINK_FLAGS "-lz -lbz2 -llzma -lrpm -lrpmio"
)

install(TARGETS drpm DESTINATION ${LIB_INSTALL_DIR})
install(FILES drpm.h DESTINATION ${INCLUDE_INSTALL_DIR})
install(FILES drpm.pc DESTINATION ${LIB_INSTALL_DIR}/pkgconfig)
