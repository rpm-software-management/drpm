set(DRPM_SOURCES drpm.c drpm_apply.c drpm_block.c drpm_compstrm.c drpm_decompstrm.c drpm_deltarpm.c drpm_diff.c drpm_make.c drpm_options.c drpm_read.c drpm_rpm.c drpm_search.c drpm_utils.c drpm_write.c)

set(DRPM_VERSION_MAJOR 0)
set(DRPM_VERSION_MINOR 3)
set(DRPM_VERSION_PATCH 0)

set(DRPM_VERSION ${DRPM_VERSION_MAJOR}.${DRPM_VERSION_MINOR}.${DRPM_VERSION_PATCH})
set(DRPM_SOVERSION ${DRPM_VERSION_MAJOR})

set(CMAKE_BUILD_TYPE RelWithDebInfo)

if (NOT ${CMAKE_SIZEOF_VOID_P} EQUAL 8)
   set(ARCH_LESS_64BIT 1)
endif()

configure_file(config.h.in ${CMAKE_BINARY_DIR}/config.h)

add_library(drpm SHARED ${DRPM_SOURCES})

set_source_files_properties(${DRPM_SOURCES} PROPERTIES
   COMPILE_FLAGS "-std=c99 -pedantic -Wall -Wextra -DHAVE_CONFIG_H -I${CMAKE_BINARY_DIR}"
)

target_link_libraries(drpm ${ZLIB_LIBRARIES} ${BZIP2_LIBRARIES} ${LIBLZMA_LIBRARIES} lz ${RPM_LIBRARIES} ${LIBCRYPTO_LIBRARIES})

set_target_properties(drpm PROPERTIES
   VERSION ${DRPM_VERSION}
   SOVERSION ${DRPM_SOVERSION}
)

install(TARGETS drpm DESTINATION ${LIB_INSTALL_DIR})
install(FILES drpm.h DESTINATION ${INCLUDE_INSTALL_DIR})
