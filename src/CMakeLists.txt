set(bcrypt_ext_SRC_DIR ${PROJECT_SOURCE_DIR}/bcrypt-ruby/ext/mri)

set(bcryptw_INCLUDE_DIR
    ${PROJECT_SOURCE_DIR}/include CACHE STRING "bcryptw include directory")

include_directories(
    ${bcryptw_INCLUDE_DIR}
    ${bcrypt_ext_SRC_DIR}
    )
set(SRC
    bcryptw.cpp
    wrapper1.c
    ${bcrypt_ext_SRC_DIR}/crypt_blowfish.c
    ${bcrypt_ext_SRC_DIR}/crypt_gensalt.c
    )

add_library(bcryptw STATIC ${SRC})

set_property(TARGET bcryptw PROPERTY VERSION ${bcryptw_VERSION})

install(
    TARGETS bcryptw EXPORT bcryptwTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)

install(
    FILES "${PROJECT_SOURCE_DIR}/include/bcryptw/bcryptw.hpp"
    DESTINATION include/bcryptw
    COMPONENT Devel)

install(
    EXPORT bcryptwTargets
    FILE bcryptw-targets.cmake
    NAMESPACE bcryptw::
    DESTINATION lib/cmake/bcryptw)

install(FILES
    "${PROJECT_SOURCE_DIR}/cmake/bcryptw-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/bcryptw/bcryptw-config-version.cmake"
    DESTINATION lib/cmake/bcryptw
    COMPONENT Devel)
