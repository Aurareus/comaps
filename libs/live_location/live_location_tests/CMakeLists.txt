project(live_location_tests)

set(SRC
  crypto_tests.cpp
  test_helpers.cpp
  test_helpers.hpp
)

omim_add_test(${PROJECT_NAME} ${SRC} NO_PLATFORM_INIT)

# Published third-party vectors and the NLL vectors live with the Python reference implementation.
target_compile_definitions(${PROJECT_NAME} PRIVATE NLL_VECTORS_DIR="${OMIM_ROOT}/tools/python/live_location/vectors")

target_link_libraries(${PROJECT_NAME}
  PRIVATE
    cppjansson
    live_location
)
