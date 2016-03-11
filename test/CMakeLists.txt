
set(bcryptw_INCLUDE_DIR
    ${PROJECT_SOURCE_DIR}/include CACHE STRING "bcryptw include directory")

include_directories(
    ${bcryptw_INCLUDE_DIR}
    )
set(SRC
    test.cpp
    )

add_executable(test1 ${SRC})
target_link_libraries(test1 bcryptw crypto)
