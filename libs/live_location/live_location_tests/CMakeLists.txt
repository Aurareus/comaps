project(live_location_tests)

set(SRC
  channel_tests.cpp
  crypto_tests.cpp
  fake_relay.cpp
  fake_relay.hpp
  json_profile_tests.cpp
  manager_tests.cpp
  marks_tests.cpp
  pairing_tests.cpp
  relay_pool_tests.cpp
  scenario.cpp
  scenario.hpp
  sharing_tests.cpp
  store_tests.cpp
  test_helpers.cpp
  test_helpers.hpp
  thread_executor_tests.cpp
  vectors_tests.cpp
)

omim_add_test(${PROJECT_NAME} ${SRC} NO_PLATFORM_INIT)

# Published third-party vectors and the NLL vectors live with the Python reference implementation.
target_compile_definitions(${PROJECT_NAME} PRIVATE NLL_VECTORS_DIR="${OMIM_ROOT}/tools/python/live_location/vectors")

target_link_libraries(${PROJECT_NAME}
  PRIVATE
    cppjansson
    live_location
)
