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
)

omim_add_library(${PROJECT_NAME} ${SRC})

# The SHA-256 shim compiles libsecp256k1's internal hash implementation (decision D9), whose header
# also defines helpers that the shim does not use.
target_include_directories(${PROJECT_NAME} PRIVATE ${OMIM_ROOT}/3party/secp256k1/src)
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
)

omim_add_test_subdirectory(live_location_tests)
