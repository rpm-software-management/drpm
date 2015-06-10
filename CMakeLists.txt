cmake_minimum_required(VERSION 2.8)

project(drpm)

add_custom_target(dist COMMAND ${CMAKE_MAKE_PROGRAM} package_source)
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure)

set(CPACK_PACKAGE_NAME ${CMAKE_PROJECT_NAME})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "A small library for fetching information from deltarpm packages")
set(CPACK_PACKAGE_CONTACT "Matej Chalk <mchalk@redhat.com>")
set(CPACK_PACKAGE_VERSION_MAJOR 0)
set(CPACK_PACKAGE_VERSION_MINOR 1)
set(CPACK_PACKAGE_VERSION_PATCH 3)
set(CPACK_SOURCE_IGNORE_FILES "/tmp/" "/build/" "/pkg/" "/html/" "/latex/" "drpm.spec" "\\\\.git" ".*~" ".*\\\\.o")
set(CPACK_SOURCE_GENERATOR "TBZ2")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")

include(CPack)

enable_testing()

add_subdirectory(src)
add_subdirectory(test)
add_subdirectory(doc)

install(FILES drpm.pc DESTINATION ${LIB_INSTALL_DIR}/pkgconfig)
