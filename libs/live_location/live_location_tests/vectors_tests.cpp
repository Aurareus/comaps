#include "testing/testing.hpp"

#include "live_location/live_location_tests/test_helpers.hpp"

#include "live_location/crypto/nip44.hpp"
#include "live_location/crypto/random.hpp"
#include "live_location/crypto/schnorr.hpp"
#include "live_location/crypto/x25519.hpp"
#include "live_location/encoding/base64.hpp"
#include "live_location/protocol/channel.hpp"
#include "live_location/protocol/common.hpp"
#include "live_location/protocol/constants.hpp"
#include "live_location/protocol/invite.hpp"
#include "live_location/protocol/pairing.hpp"
#include "live_location/protocol/stream.hpp"

#include "cppjansson/cppjansson.hpp"

#include <string>
#include <vector>

// Replays tools/python/live_location/make_vectors.py step by step with the same deterministic
// randomness, and checks every value of vectors/nll1_vectors.json: the C++ implementation must produce
// the same bytes as the Python reference.
namespace vectors_tests
{
using namespace live_location;
using namespace live_location_tests;

// The TestRng of the vectors, logging what each step consumes, as RecordingRng does.
class RecordingRng final : public crypto::Rng
{
public:
  explicit RecordingRng(std::string_view seed) : m_rng(AsBytes(seed)) {}

  void Fill(uint8_t * data, size_t size) override
  {
    m_rng.Fill(data, size);
    m_log.push_back(ToHex(ByteSpan(data, size)));
  }

  std::vector<std::string> Take() { return std::exchange(m_log, {}); }

private:
  crypto::TestRng m_rng;
  std::vector<std::string> m_log;
};

json_t const * Field(json_t const * root, char const * name)
{
  return base::GetJSONObligatoryField(root, name);
}

std::string Str(json_t const * root, char const * name)
{
  return FromJSONObject<std::string>(root, name);
}

int64_t Int(json_t const * root, char const * name)
{
  return json_integer_value(Field(root, name));
}

std::vector<std::string> Strings(json_t const * array)
{
  std::vector<std::string> out;
  for (size_t i = 0; i < json_array_size(array); ++i)
    out.emplace_back(json_string_value(json_array_get(array, i)));
  return out;
}

void CheckRandom(json_t const * step, char const * name, std::vector<std::string> const & consumed)
{
  TEST_EQUAL(Strings(Field(step, name)), consumed, (name));
}

void CheckEvent(json_t const * expected, nostr::Event const & event, std::string const & what)
{
  TEST_EQUAL(event.m_id, Str(expected, "id"), (what));
  TEST_EQUAL(event.m_pubkey, Str(expected, "pubkey"), (what));
  TEST_EQUAL(event.m_createdAt, Int(expected, "created_at"), (what));
  TEST_EQUAL(event.m_kind, Int(expected, "kind"), (what));
  json_t const * tags = Field(expected, "tags");
  TEST_EQUAL(event.m_tags.size(), json_array_size(tags), (what));
  for (size_t i = 0; i < event.m_tags.size() && i < json_array_size(tags); ++i)
    TEST_EQUAL(event.m_tags[i], Strings(json_array_get(tags, i)), (what, i));
  TEST_EQUAL(event.m_content, Str(expected, "content"), (what));
  TEST_EQUAL(event.m_sig, Str(expected, "sig"), (what));
  TEST_EQUAL(nostr::Serialize(event), Str(expected, "serialized"), (what));
  TEST(nostr::Verify(event), (what));
}

std::string PlaintextHex(json::Value const & message, size_t size)
{
  return ToHex(EncodePlaintext(message, size));
}

UNIT_TEST(Vectors_ReproducedByteForByte)
{
  base::Json const json(ReadFile(VectorsPath("nll1_vectors.json")));
  json_t const * v = json.get();
  TEST_EQUAL(Int(v, "version"), 1, ());
  RecordingRng rng("nll1 test vectors");
  int64_t constexpr T = 1'760'000'000;

  // 1. Key derivation.
  json_t const * derive = Field(v, "derive_secp_key");
  for (size_t i = 0; i < json_array_size(derive); ++i)
  {
    json_t const * t = json_array_get(derive, i);
    Key const sk = DeriveSecpKey(Hex(Str(t, "prk")), Str(t, "purpose"));
    TEST_EQUAL(ToHex(sk), Str(t, "secret"), (i));
    TEST_EQUAL(ToHex(crypto::GetXOnlyPublicKey(sk)), Str(t, "pubkey"), (i));
  }

  // 2. Plaintext padding.
  json_t const * plaintext = Field(v, "plaintext");
  TEST_EQUAL(PlaintextHex(ToJson(StreamEnd{7, T}), kSizeStream), Str(plaintext, "encoded_hex"), ());

  // 3. Pairing.
  json_t const * pairing = Field(v, "pairing");
  json_t const * inviteJson = Field(pairing, "invite");
  Relays const relaysA = {"wss://nos.lol", "wss://nostr.mom", "wss://relay.primal.net"};
  Relays const relaysB = {"wss://nos.lol", "wss://relay.nostr.net"};
  Inviter inviter(relaysA, rng, T);
  CheckRandom(pairing, "inviter_random", rng.Take());
  Invite const & invite = inviter.GetInvite();
  TEST_EQUAL(ToHex(*invite.m_psk), Str(inviteJson, "psk"), ());
  TEST_EQUAL(ToHex(inviter.PairingSecretForVectors()), Str(inviteJson, "inviter_pairing_secret"), ());
  TEST_EQUAL(ToHex(invite.m_ipk), Str(inviteJson, "inviter_pairing_pubkey"), ());
  TEST_EQUAL(invite.m_expiresAt, Int(inviteJson, "expires_at"), ());
  TEST_EQUAL(ToHex(invite.Encode()), Str(inviteJson, "encoded_hex"), ());
  TEST_EQUAL(invite.Link(), Str(inviteJson, "link"), ());
  TEST_EQUAL(ToHex(inviter.MacKeyForVectors()), Str(inviteJson, "mac_key"), ());

  auto const fromLink = Invite::FromLink(invite.Link());
  TEST(fromLink, ());
  Joiner joiner(*fromLink, "Bob", relaysB, rng, T + 5);
  auto const joinerRandom = rng.Take();
  CheckRandom(pairing, "joiner_random", joinerRandom);
  TEST_EQUAL(joinerRandom.size(), 2, ());

  json_t const * step0 = Field(pairing, "step0_commit");
  nostr::Event const m0 = joiner.CommitEvent(rng, T + 5);
  CheckRandom(step0, "random", rng.Take());
  TEST_EQUAL(joinerRandom[0], Str(step0, "joiner_pairing_secret"), ());
  TEST_EQUAL(ToHex(joiner.Jpk()), Str(step0, "joiner_pairing_pubkey"), ());
  TEST_EQUAL(ToHex(crypto::X25519PublicKey(HexKey(joinerRandom[1]))), Str(step0, "joiner_ephemeral_public"), ());
  TEST_EQUAL(ToHex(joiner.C()), Str(step0, "commitment"), ());
  CheckEvent(Field(step0, "event"), m0, "step 0");
  TEST_EQUAL(ToHex(invite.Prologue(joiner.Jpk(), joiner.C())), Str(pairing, "prologue_hex"), ());

  json_t const * step1 = Field(pairing, "step1_noise1");
  auto const out1 = inviter.OnEvent(m0, rng, T + 6);
  TEST(out1 && out1->m_publish, ());
  CheckRandom(step1, "random", rng.Take());
  TEST_EQUAL(PlaintextHex(Pair1Json(), kSizeControl), Str(step1, "payload_hex"), ());
  TEST_EQUAL(ToHex(*Base64Decode(out1->m_publish->m_content)), Str(step1, "noise_message_hex"), ());
  CheckEvent(Field(step1, "event"), *out1->m_publish, "step 1");

  json_t const * step2 = Field(pairing, "step2_noise2");
  auto const out2 = joiner.OnEvent(*out1->m_publish, rng, T + 7);
  TEST(out2 && out2->m_publish && out2->m_showCode, ());
  CheckRandom(step2, "random", rng.Take());
  TEST_EQUAL(PlaintextHex(ToJson(Pair2{"Bob", relaysB}), kSizeControl), Str(step2, "payload_hex"), ());
  TEST_EQUAL(ToHex(*Base64Decode(out2->m_publish->m_content)), Str(step2, "noise_message_hex"), ());
  CheckEvent(Field(step2, "event"), *out2->m_publish, "step 2");
  TEST(joiner.K1() && joiner.K2(), ());
  Key const k1 = *joiner.K1();
  Key const k2 = *joiner.K2();

  auto const request = inviter.OnEvent(*out2->m_publish, rng, T + 8);
  TEST(request && request->m_showCode, ());
  TEST(rng.Take().empty(), ("reading step 2 draws nothing"));

  json_t const * step3 = Field(pairing, "step3_confirm");
  int64_t const decidedAt = Int(step3, "now");
  int64_t const ep = EpochOf(decidedAt - kMaxFutureSkew);
  auto const done = inviter.Decide(true, "Alice", relaysA, rng, decidedAt);
  CheckRandom(step3, "random", rng.Take());
  TEST_EQUAL(ToHex(ConfirmKey(k1)), Str(step3, "confirm_key"), ());
  Pair3 pair3;
  pair3.m_ok = true;
  pair3.m_name = "Alice";
  pair3.m_relays = relaysA;
  pair3.m_epoch = ep;
  TEST_EQUAL(PlaintextHex(ToJson(pair3), kSizeControl), Str(step3, "plaintext_hex"), ());
  CheckEvent(Field(step3, "event"), *done.m_publish, "step 3");
  ContactPtr const cA = done.m_contact;
  TEST(cA && !cA->m_confirmed, ());

  json_t const * confirmation = Field(pairing, "joiner_confirmation");
  auto const fin = joiner.OnEvent(*done.m_publish, rng, T + 21);
  TEST(fin && fin->m_contact && fin->m_publish, ());
  CheckRandom(confirmation, "random", rng.Take());
  ContactPtr const cB = fin->m_contact;
  State firstState;
  firstState.m_seq = 1;
  firstState.m_ts = T + 21;
  firstState.m_relays = relaysB;
  TEST_EQUAL(PlaintextHex(ToJson(firstState), kSizeControl), Str(confirmation, "plaintext_hex"), ());
  CheckEvent(Field(confirmation, "event"), *fin->m_publish, "joiner confirmation");
  bool const confirms = ReadControl(*cA, *fin->m_publish, T + 22).has_value();
  TEST_EQUAL(confirms, json_is_true(Field(confirmation, "confirms_on_inviter_side")), ());
  TEST(cA->m_confirmed, ());

  json_t const * result = Field(pairing, "result");
  TEST_EQUAL(ToHex(inviter.HandshakeHash()), Str(result, "handshake_hash"), ());
  TEST_EQUAL(ToHex(joiner.HandshakeHash()), Str(result, "handshake_hash"), ());
  TEST_EQUAL(ToHex(k1), Str(result, "split_i2r"), ());
  TEST_EQUAL(ToHex(k2), Str(result, "split_r2i"), ());
  TEST_EQUAL(cA->m_sas, Str(result, "sas"), ());
  TEST_EQUAL(cB->m_sas, Str(result, "sas"), ());
  TEST_EQUAL(ep, Int(result, "pairing_epoch"), ());
  json_t const * shown = Field(result, "shown_to_inviter");
  TEST_EQUAL(*request->m_showCode->m_name, Str(shown, "name"), ());
  TEST_EQUAL(*request->m_showCode->m_relays, Strings(Field(shown, "relays")), ());
  TEST_EQUAL(request->m_showCode->m_sas, Str(shown, "sas"), ());

  json_t const * chains = Field(pairing, "channel_keys");
  TEST_EQUAL(json_array_size(chains), 6, ());
  for (size_t i = 0; i < json_array_size(chains); ++i)
  {
    json_t const * t = json_array_get(chains, i);
    Key const & root = Str(t, "direction") == "inviter_to_joiner" ? k1 : k2;
    Direction const d = Direction::FromRoot(root, ep).At(Int(t, "epoch"));
    TEST_EQUAL(ToHex(d.ChainKey()), Str(t, "chain_key"), (i));
    TEST_EQUAL(ToHex(d.SigningKey()), Str(t, "signing_secret"), (i));
    TEST_EQUAL(d.Pubkey(), Str(t, "pubkey"), (i));
    TEST_EQUAL(ToHex(d.ConversationKey()), Str(t, "conversation_key"), (i));
  }

  // 4. Grant, location, stream end, control end, signal.
  json_t const * grantJson = Field(v, "state_with_grant");
  int64_t const now = Int(grantJson, "now");
  Stream stream = Stream::Create(rng);
  CheckRandom(grantJson, "stream_random", rng.Take());
  TEST_EQUAL(ToHex(stream.m_secret), Str(grantJson, "stream_secret"), ());
  TEST_EQUAL(stream.Pubkey(), Str(grantJson, "stream_pubkey"), ());
  TEST_EQUAL(ToHex(stream.m_key), Str(grantJson, "stream_key"), ());
  State granted;
  granted.m_seq = 1;
  granted.m_ts = now;
  granted.m_relays = relaysA;
  granted.m_share = Share{now + 3600, stream.Pubkey(), stream.m_key};
  nostr::Event const g = ControlEvent(*cA, ToJson(granted), rng, now);
  CheckRandom(grantJson, "random", rng.Take());
  TEST_EQUAL(PlaintextHex(ToJson(granted), kSizeControl), Str(grantJson, "plaintext_hex"), ());
  CheckEvent(Field(grantJson, "event"), g, "state with grant");
  auto const decrypted = ReadControl(*cB, g, now + 1);
  TEST(decrypted && decrypted->m_share, ());
  json_t const * expectedShare = Field(Field(grantJson, "decrypted"), "share");
  TEST_EQUAL(decrypted->m_share->m_until, Int(expectedShare, "until"), ());
  TEST_EQUAL(decrypted->m_share->m_pk, Str(expectedShare, "pk"), ());
  TEST_EQUAL(Base64Encode(decrypted->m_share->m_key), Str(expectedShare, "key"), ());
  TEST_EQUAL(decrypted->m_relays, relaysA, ());

  json_t const * locJson = Field(v, "location");
  Location fix;
  fix.m_ts = (now + 5) * 1000;
  fix.m_lat = 52.5200066;
  fix.m_lon = 13.404954;
  fix.m_acc = 8.0;
  fix.m_spd = 1.4;
  fix.m_brg = 271.0;
  nostr::Event const loc = stream.LocationEvent(fix, rng, now + 5);
  CheckRandom(locJson, "random", rng.Take());
  fix.m_seq = 1;
  TEST_EQUAL(PlaintextHex(ToJson(fix), kSizeStream), Str(locJson, "plaintext_hex"), ());
  CheckEvent(Field(locJson, "event"), loc, "location");
  auto const position = ReadStream(*decrypted->m_share, loc, 0, now + 6);
  TEST(position && std::holds_alternative<Location>(*position), ());
  auto const & p = std::get<Location>(*position);
  json_t const * expectedLoc = Field(locJson, "decrypted");
  TEST_EQUAL(p.m_lat, json_real_value(Field(expectedLoc, "lat")), ());
  TEST_EQUAL(p.m_lon, json_real_value(Field(expectedLoc, "lon")), ());
  TEST_EQUAL(p.m_ts, Int(expectedLoc, "ts"), ());

  json_t const * endJson = Field(v, "stream_end");
  nostr::Event const se = stream.EndEvent(rng, now + 30);
  CheckRandom(endJson, "random", rng.Take());
  TEST_EQUAL(PlaintextHex(ToJson(StreamEnd{2, now + 30}), kSizeStream), Str(endJson, "plaintext_hex"), ());
  CheckEvent(Field(endJson, "event"), se, "stream end");

  json_t const * ceJson = Field(v, "state_without_share");
  State ended;
  ended.m_seq = 2;
  ended.m_ts = now + 30;
  ended.m_relays = relaysA;
  nostr::Event const ce = ControlEvent(*cA, ToJson(ended), rng, now + 30);
  CheckRandom(ceJson, "random", rng.Take());
  CheckEvent(Field(ceJson, "event"), ce, "state without share");

  json_t const * sigJson = Field(v, "signal");
  nostr::Event const sig = WatchSignal(*cB, now + 150, rng, now + 40);
  CheckRandom(sigJson, "random", rng.Take());
  CheckEvent(Field(sigJson, "event"), sig, "signal");

  // 5. Inbox subscription.
  json_t const * inbox = Field(v, "inbox_filters");
  Bytes const decoySeed = Hex(Str(inbox, "decoy_seed"));
  TEST_EQUAL(DecoyKeys(decoySeed, Int(inbox, "epoch"), 7), Strings(Field(inbox, "decoys")), ());
  auto const filters = InboxFilters({cA}, decoySeed, Int(inbox, "epoch"), Int(inbox, "now"));
  json_t const * expectedFilters = Field(inbox, "filters");
  TEST_EQUAL(filters.size(), json_array_size(expectedFilters), ());
  for (size_t i = 0; i < filters.size() && i < json_array_size(expectedFilters); ++i)
  {
    json_t const * f = json_array_get(expectedFilters, i);
    TEST_EQUAL(filters[i].m_authors, Strings(Field(f, "authors")), (i));
    json_t const * kinds = Field(f, "kinds");
    TEST_EQUAL(filters[i].m_kinds.size(), 1, (i));
    TEST_EQUAL(filters[i].m_kinds[0], json_integer_value(json_array_get(kinds, 0)), (i));
    json_t const * since = base::GetJSONOptionalField(f, "since");
    TEST_EQUAL(filters[i].m_since.has_value(), since != nullptr, (i));
    if (since != nullptr)
      TEST_EQUAL(*filters[i].m_since, json_integer_value(since), (i));
  }

  // 6. NIP-44 with a protocol conversation key.
  json_t const * profile = Field(v, "nip44_profile");
  ByteArray<32> nonce;
  for (uint8_t i = 0; i < 32; ++i)
    nonce[i] = i;
  auto const pt = EncodePlaintext(ToJson(StreamEnd{1, T}), kSizeStream);
  TEST_EQUAL(ToHex(pt), Str(profile, "plaintext_hex"), ());
  TEST_EQUAL(nip44::Encrypt(pt, HexKey(Str(profile, "conversation_key")), nonce), Str(profile, "payload"), ());
}
}  // namespace vectors_tests
