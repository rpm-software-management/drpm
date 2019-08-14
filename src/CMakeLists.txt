set(DRPM_SOVERSION ${DRPM_MAJOR_VERSION})

set(CMAKE_BUILD_TYPE RelWithDebInfo)

if (NOT ${CMAKE_SIZEOF_VOID_P} EQUAL 8)
   set(ARCH_LESS_64BIT 1)
endif()

configure_file(config.h.in ${CMAKE_BINARY_DIR}/config.h)

add_library(drpm SHARED ${DRPM_SOURCES})

set_source_files_properties(${DRPM_SOURCES} PROPERTIES
   COMPILE_FLAGS "-std=c99 -pedantic -Wall -Wextra -DHAVE_CONFIG_H -I${CMAKE_BINARY_DIR}"
)

target_link_libraries(drpm ${DRPM_LINK_LIBRARIES})

set_target_properties(drpm PROPERTIES
   VERSION ${DRPM_VERSION}
   SOVERSION ${DRPM_SOVERSION}
)

install(TARGETS drpm LIBRARY DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR})
install(FILES drpm.h DESTINATION ${CMAKE_INSTALL_FULL_INCLUDEDIR})
