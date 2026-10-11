#pragma once

#include "live_location/crypto/bytes.hpp"
#include "live_location/crypto/random.hpp"
#include "live_location/nostr/event.hpp"
#include "live_location/protocol/json.hpp"

#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace live_location
{
/// "nll1:" || purpose (spec §3).
Bytes Label(std::string_view purpose);

/// UTC days.
int64_t EpochOf(int64_t unixTime);
int64_t EpochEnd(int64_t epoch);

/// The first valid secp256k1 secret among HKDF-Expand(prk, label(purpose) || u8(ctr), 32), ctr = 0, 1, …
Key DeriveSecpKey(ByteSpan prk, std::string_view purpose);
/// 32 random bytes until they form a valid secret key.
Key RandomSecpKey(crypto::Rng & rng);
/// An integer in [0, n) from 32 random bits (the bias, below n / 2^32, is irrelevant for delays and
/// order).
uint32_t RandomBelow(crypto::Rng & rng, uint32_t n);

/// Fisher-Yates, drawing as the Python reference does.
template <typename T>
void Shuffle(std::vector<T> & items, crypto::Rng & rng)
{
  for (size_t i = items.size(); i > 1; --i)
    std::swap(items[i - 1], items[RandomBelow(rng, static_cast<uint32_t>(i))]);
}

/// The NIP-44 payload of `message` padded to `size`, with a fresh nonce from `rng`.
std::string Seal(json::Value const & message, size_t size, Key const & conversationKey, crypto::Rng & rng);
/// The decrypted, decoded plaintext (spec §12 item 5), or nothing.
std::optional<json::Value> OpenSealed(std::string_view content, Key const & conversationKey);

/// A signed event; `rng` provides BIP-340's auxiliary randomness.
nostr::Event SignEvent(Key const & secretKey, int64_t createdAt, int64_t kind, nostr::Tags tags, std::string content,
                       crypto::Rng & rng);

/// The envelope checks every receiver applies before decrypting (spec §12 items 1–4): integer kind and
/// created_at >= 0, the expected kind and author (`expectedPubkeys` null: any author), a valid id and
/// signature, created_at at most 300 s ahead, the expected `d` and `p` tags, and for kind 30484 an
/// `expiration` of 1–10 ASCII digits in the future.
bool CheckEvent(nostr::Event const & event, std::set<std::string> const * expectedPubkeys, int64_t kind,
                std::optional<std::string_view> d, int64_t now, std::optional<std::string_view> pTag = {});
}  // namespace live_location
