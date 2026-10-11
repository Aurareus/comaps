project(live_location)

# Decentralized, end-to-end-encrypted live location sharing: the NLL v1 protocol
# (docs/LIVE_LOCATION_PROTOCOL.md) and its runtime. No UI and no platform code.

set(SRC
  crypto/bytes.cpp
  crypto/bytes.hpp
  crypto/chacha.cpp
  crypto/chacha.hpp
  crypto/hkdf.cpp
  crypto/hkdf.hpp
  crypto/nip44.cpp
  crypto/nip44.hpp
  crypto/noise.cpp
  crypto/noise.hpp
  crypto/random.cpp
  crypto/random.hpp
  crypto/schnorr.cpp
  crypto/schnorr.hpp
  crypto/secp256k1_sha256.c
  crypto/secp256k1_sha256.h
  crypto/sha256.cpp
  crypto/sha256.hpp
  crypto/x25519.cpp
  crypto/x25519.hpp
  encoding/base64.cpp
  encoding/base64.hpp
  encoding/binary.cpp
  encoding/binary.hpp
  executor.hpp
  nostr/event.cpp
  nostr/event.hpp
  nostr/filter.cpp
  nostr/filter.hpp
  nostr/relay_message.cpp
  nostr/relay_message.hpp
  protocol/channel.cpp
  protocol/channel.hpp
  protocol/common.cpp
  protocol/common.hpp
  protocol/constants.hpp
  protocol/invite.cpp
  protocol/invite.hpp
  protocol/json.cpp
  protocol/json.hpp
  protocol/messages.cpp
  protocol/messages.hpp
  protocol/pairing.cpp
  protocol/pairing.hpp
  protocol/persist.cpp
  protocol/persist.hpp
  protocol/stream.cpp
  protocol/stream.hpp
  relay/relay_pool.cpp
  relay/relay_pool.hpp
  relay/transport.hpp
  store/store.cpp
  store/store.hpp
)

omim_add_library(${PROJECT_NAME} ${SRC})

# CoMaps builds with -ffast-math. Protocol code needs IEEE semantics: the JSON profile must see the
# infinity of an overflowing number, and the shortest round-trip printing of doubles must be exact.
# This covers the code compiled here only: the linker may take an inline function of a shared header
# (std::isfinite, unless inlined) from another library's fast-math copy, so json.cpp avoids those.
target_compile_options(${PROJECT_NAME} PRIVATE $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-fno-fast-math>)

# The SHA-256 shim compiles libsecp256k1's internal hash implementation (decision D9), whose header
# also defines helpers that the shim does not use.
target_include_directories(${PROJECT_NAME} PRIVATE
  ${OMIM_ROOT}/3party/secp256k1/src
  ${OMIM_ROOT}/3party/fast_double_parser/include
)
set_source_files_properties(crypto/secp256k1_sha256.c PROPERTIES
  COMPILE_OPTIONS "$<$<NOT:$<C_COMPILER_ID:MSVC>>:-Wno-unused-function>"
  SKIP_UNITY_BUILD_INCLUSION ON
)

target_link_libraries(${PROJECT_NAME}
  PRIVATE
    monocypher
    secp256k1
    $<$<PLATFORM_ID:Windows>:bcrypt>  # BCryptGenRandom
  PUBLIC
    base
    jansson::jansson
)

omim_add_test_subdirectory(live_location_tests)
