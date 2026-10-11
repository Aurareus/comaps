#include "testing/testing.hpp"

#include "live_location/live_location_tests/scenario.hpp"
#include "live_location/live_location_tests/test_helpers.hpp"

#include "live_location/crypto/noise.hpp"
#include "live_location/encoding/binary.hpp"
#include "live_location/protocol/constants.hpp"
#include "live_location/protocol/persist.hpp"
#include "live_location/store/store.hpp"

#include <cstdio>
#include <filesystem>
#include <map>
#include <memory>
#include <string>

// The store: its encoding, pairings that survive restarts at every step, the encrypted file, and the
// rotation of keys when secrets are erased (design doc §8.5, §10.4).
namespace store_tests
{
using namespace live_location;
using namespace live_location_tests;

std::string TempPath(std::string const & name)
{
  return (std::filesystem::temp_directory_path() / ("nll_store_test_" + name)).string();
}

UNIT_TEST(Binary_RoundTripAndLimits)
{
  binary::Writer writer;
  writer.U8(7);
  writer.U32(0xdeadbeef);
  writer.I64(-1234567890123);
  writer.Bool(true);
  writer.String("café");
  Key const key = ScenarioRng().Get<32>();
  writer.Secret(key);
  writer.OptionalSecret({});
  TEST_EQUAL(writer.SecretDigests().size(), 1, ("one secret written"));
  SecretBytes const data = writer.Finish();

  binary::Reader reader(data);
  TEST_EQUAL(reader.U8(), 7, ());
  TEST_EQUAL(reader.U32(), 0xdeadbeef, ());
  TEST_EQUAL(reader.I64(), -1234567890123, ());
  TEST(reader.Bool(), ());
  TEST_EQUAL(reader.String(), "café", ());
  TEST_EQUAL(ToHex(reader.Secret()), ToHex(key), ());
  TEST(!reader.OptionalSecret(), ());
  TEST(reader.AtEnd(), ());

  TEST(Throws<binary::FormatError>([&] { binary::Reader(ByteSpan(data.data(), 3)).U32(); }), ("truncated"));
  Bytes const huge = {0xff, 0xff, 0xff, 0xff, 1, 2};
  TEST(Throws<binary::FormatError>([&] { binary::Reader(huge).Count(1); }), ("a count beyond the data"));
  TEST(Throws<binary::FormatError>([&] { binary::Reader(huge).String(); }), ("a length beyond the data"));
  Bytes const two = {2};
  TEST(Throws<binary::FormatError>([&] { binary::Reader(two).Bool(); }), ("not a boolean"));
}

UNIT_TEST(Binary_HandshakeSurvivesARestart)
{
  auto & rng = ScenarioRng();
  Key const psk = rng.Get<32>();
  Bytes const prologue = {1, 2, 3};
  noise::HandshakeState initiator(true, prologue, psk, rng.Get<32>());
  noise::HandshakeState responder(false, prologue, psk, rng.Get<32>());
  auto const m1 = initiator.WriteMessage(AsBytes("one"));

  binary::Writer writer;
  initiator.Save(writer);
  SecretBytes const saved = writer.Finish();
  binary::Reader reader(saved);
  noise::HandshakeState restored = noise::HandshakeState::Load(reader);

  TEST(responder.ReadMessage(*m1), ());
  auto const m2 = responder.WriteMessage(AsBytes("two"));
  auto const payload = restored.ReadMessage(*m2);
  TEST(payload && std::string(payload->begin(), payload->end()) == "two", ("the restored state reads message 2"));
  TEST_EQUAL(ToHex(restored.Split().m_k1), ToHex(responder.Split().m_k1), ("and derives the same keys"));
}

/// Saves and loads a pairing party, as an app restart would.
template <typename Party>
std::unique_ptr<Party> Restart(Party const & party, std::map<std::string, ContactPtr> & contacts)
{
  binary::Writer writer;
  party.Save(writer, [&](ContactPtr const & contact)
  {
    for (auto const & [id, c] : contacts)
      if (c == contact)
        return id;
    std::string const id = "c" + std::to_string(contacts.size());
    contacts[id] = contact;
    return id;
  });
  SecretBytes const saved = writer.Finish();
  binary::Reader reader(saved);
  auto out = Party::Load(reader, [&](std::string const & id) { return contacts.at(id); });
  TEST(reader.AtEnd(), ());
  return out;
}

UNIT_TEST(Binary_PairingSurvivesRestartsAtEveryStep)
{
  auto & rng = ScenarioRng();
  std::map<std::string, ContactPtr> contacts;
  ModelRelay relay;
  auto inviter = std::make_unique<Inviter>(kRelaysA, rng, kT0, 86400);
  std::string const link = inviter->GetInvite().Link();
  auto joiner = JoinerStarts(link, "Bob", relay, kT0);
  joiner = Restart(*joiner, contacts);
  inviter = Restart(*inviter, contacts);
  Online(*inviter, relay, kT0 + 10);  // step 1
  inviter = Restart(*inviter, contacts);
  joiner = Restart(*joiner, contacts);
  auto const shown = Online(*joiner, relay, kT0 + 20);  // step 2
  TEST(shown.size() == 1 && shown[0].m_showCode, ());
  joiner = Restart(*joiner, contacts);
  TEST(joiner->K1(), ("the split keys survive"));
  auto const request = Online(*inviter, relay, kT0 + 30);
  TEST(request.size() == 1 && request[0].m_showCode && request[0].m_showCode->m_name == std::string("Bob"), ());
  inviter = Restart(*inviter, contacts);
  auto const decided = inviter->Decide(true, "Alice", kRelaysA, rng, kT0 + 40);
  relay.Publish(*decided.m_publish);
  inviter = Restart(*inviter, contacts);
  TEST(inviter->GetContact() == decided.m_contact, ("the pairing keeps its contact through the store's ids"));
  auto const finished = Online(*joiner, relay, kT0 + 50);
  TEST(finished.size() == 1 && finished[0].m_contact, ());
  Contact const & ci = *decided.m_contact;
  Contact const & cj = *finished[0].m_contact;
  TEST(ci.m_sas == cj.m_sas && ToHex(ci.m_outgoing.ChainKey()) == ToHex(cj.m_incoming.ChainKey()),
       ("a pairing restarted at every step completes with the same keys"));

  // Conflict watching survives too: a second joiner later flags the contact on both sides.
  joiner = Restart(*joiner, contacts);
  inviter = Restart(*inviter, contacts);
  JoinerStarts(link, "Mallory", relay, kT0 + 60);
  auto const flagged = Online(*inviter, relay, kT0 + 61);
  TEST(flagged.size() == 1 && flagged[0].m_flagged && decided.m_contact->m_flagged, ());
}

UNIT_TEST(Binary_ContactRoundTrip)
{
  Paired const p = Pair("Alice", kRelaysA, "Bob", kRelaysB, kT0, false);
  Contact & original = *p.m_joinerSide;
  original.m_lastSeqIn = 17;
  original.m_seqOut = 4;
  original.m_lastCreatedOut = kT0 + 99;
  original.m_verified = true;
  binary::Writer writer;
  persist::WriteContact(writer, original);
  SecretBytes const saved = writer.Finish();
  binary::Reader reader(saved);
  ContactPtr const copy = persist::ReadContact(reader);
  TEST(copy->m_name == original.m_name && copy->m_relays == original.m_relays && copy->m_sas == original.m_sas &&
           copy->m_pairingEpoch == original.m_pairingEpoch && copy->m_joiner == original.m_joiner &&
           copy->m_lastSeqIn == 17 && copy->m_seqOut == 4 && copy->m_lastCreatedOut == kT0 + 99 && copy->m_verified &&
           copy->m_flagged == original.m_flagged && copy->m_confirmed == original.m_confirmed,
       ());
  TEST(ToHex(copy->m_outgoing.ChainKey()) == ToHex(original.m_outgoing.ChainKey()) &&
           copy->m_incoming.Epoch() == original.m_incoming.Epoch(),
       ());
  TEST_EQUAL(writer.SecretDigests().size(), 2, ("both chain keys count as secrets, also after Finish()"));
}

std::set<ByteArray<32>> Digests(std::vector<Key> const & keys)
{
  binary::Writer writer;
  for (auto const & key : keys)
    writer.Secret(key);
  return writer.SecretDigests();
}

UNIT_TEST(Store_EncryptsAndRotatesOnErasure)
{
  auto & rng = ScenarioRng();
  std::string const path = TempPath("rotation");
  std::remove(path.c_str());
  store::InsecureKeyWrapper wrapper;
  Key const a = rng.Get<32>();
  Key const b = rng.Get<32>();
  Key const c = rng.Get<32>();
  std::string const secretText = "the contents, with a name: Zoë";
  {
    store::Store store(path, wrapper, rng);
    SecretBytes contents;
    TEST(store.Load(contents) == store::Store::Result::Empty, ());
    TEST(store.Save(AsBytes(secretText), Digests({a, b})), ());
    TEST(store.LastSaveRotated() && wrapper.Aliases().size() == 1, ("the first save makes the keys"));
    std::string const firstAlias = *wrapper.Aliases().begin();

    std::string const onDisk = ReadFile(path);
    TEST(onDisk.rfind("NLLS", 0) == 0 && onDisk.find("Zo") == std::string::npos, ("the contents are encrypted"));

    TEST(store.Save(AsBytes(secretText), Digests({a, b, c})), ());
    TEST(!store.LastSaveRotated() && *wrapper.Aliases().begin() == firstAlias, ("a new secret: no rotation"));
    TEST(store.Save(AsBytes(secretText), Digests({b, c})), ());
    TEST(store.LastSaveRotated() && wrapper.Aliases().size() == 1 && *wrapper.Aliases().begin() != firstAlias,
         ("a secret erased: new keys, and the old wrapping key deleted"));
  }
  {
    // A restart reads it back.
    store::Store store(path, wrapper, rng);
    SecretBytes contents;
    TEST(store.Load(contents) == store::Store::Result::Loaded, ());
    TEST_EQUAL(std::string(contents.begin(), contents.end()), secretText, ());
    store.SetBaseline(Digests({b, c}));
    TEST(store.Save(AsBytes(secretText), Digests({c})) && store.LastSaveRotated(),
         ("the baseline set after loading catches an erasure in the first save"));
  }
  {
    // A copy of an old file, as flash memory might keep, cannot be read once its wrapping key is gone.
    std::string const copy = ReadFile(path);
    store::Store store(path, wrapper, rng);
    SecretBytes contents;
    TEST(store.Load(contents) == store::Store::Result::Loaded, ());
    store.SetBaseline(Digests({c}));
    TEST(store.Save(AsBytes(secretText), {}) && store.LastSaveRotated(), ());
    std::string const oldPath = TempPath("old_copy");
    {
      std::FILE * f = std::fopen(oldPath.c_str(), "wb");
      std::fwrite(copy.data(), 1, copy.size(), f);
      std::fclose(f);
    }
    store::Store old(oldPath, wrapper, rng);
    SecretBytes oldContents;
    TEST(old.Load(oldContents) == store::Store::Result::Unreadable, ("the old copy is unreadable"));
    std::remove(oldPath.c_str());
  }
  {
    // Tampering is detected.
    std::string data = ReadFile(path);
    data[data.size() - 3] ^= 1;
    std::FILE * f = std::fopen(path.c_str(), "wb");
    std::fwrite(data.data(), 1, data.size(), f);
    std::fclose(f);
    store::Store store(path, wrapper, rng);
    SecretBytes contents;
    TEST(store.Load(contents) == store::Store::Result::Unreadable, ("a modified file is refused"));
    store.Erase();
    TEST(wrapper.Aliases().empty() && store.Load(contents) == store::Store::Result::Empty, ("erased"));
  }
  {
    // A crash between writing the file and deleting the old wrapping key leaves an extra key: the next
    // load deletes it.
    store::Store store(path, wrapper, rng);
    TEST(store.Save(AsBytes(secretText), {}), ());
    wrapper.Wrap(rng.Get<32>());
    TEST_EQUAL(wrapper.Aliases().size(), 2, ());
    store::Store restarted(path, wrapper, rng);
    SecretBytes contents;
    TEST(restarted.Load(contents) == store::Store::Result::Loaded && wrapper.Aliases().size() == 1, ());
    restarted.Erase();
  }
}
}  // namespace store_tests
