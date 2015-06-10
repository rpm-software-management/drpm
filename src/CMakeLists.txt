set(DRPM_SOURCES drpm.c drpm_compstrm.c drpm_read.c drpm_utils.c)

set(DRPM_VERSION_MAJOR 0)
set(DRPM_VERSION_MINOR 0)
set(DRPM_VERSION_PATCH 1)

set(DRPM_VERSION ${DRPM_VERSION_MAJOR}.${DRPM_VERSION_MINOR}.${DRPM_VERSION_PATCH})
set(DRPM_SOVERSION ${DRPM_VERSION_MAJOR})

set(CMAKE_BUILD_TYPE RelWithDebInfo)

if (NOT ${CMAKE_SIZEOF_VOID_P} EQUAL 8)
   set(ARCH_32BIT 1)
endif()

configure_file(config.h.in ${CMAKE_BINARY_DIR}/config.h)

add_library(drpm SHARED ${DRPM_SOURCES})

set_source_files_properties(${DRPM_SOURCES} PROPERTIES
   COMPILE_FLAGS "-std=c99 -pedantic -Wall -Wextra -DHAVE_CONFIG_H -I${CMAKE_BINARY_DIR}"
)

set_target_properties(drpm PROPERTIES
   VERSION ${DRPM_VERSION}
   SOVERSION ${DRPM_SOVERSION}
   LINK_FLAGS "-lz -lbz2 -llzma -lrpm -lrpmio"
)

install(TARGETS drpm DESTINATION ${LIB_INSTALL_DIR})
install(FILES drpm.h DESTINATION ${INCLUDE_INSTALL_DIR})
