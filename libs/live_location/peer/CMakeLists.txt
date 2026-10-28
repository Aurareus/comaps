# A desktop peer for cross-implementation tests: the live location core over plain ws:// to a local relay.
project(live_location_peer)

set(SRC
  main.cpp
  plain_websocket.cpp
  plain_websocket.hpp
)

omim_add_executable(${PROJECT_NAME} ${SRC})

target_link_libraries(${PROJECT_NAME}
  PRIVATE
    live_location
)
