#include "testing/testing.hpp"

#include "live_location/live_location_tests/scenario.hpp"
#include "live_location/live_location_tests/test_helpers.hpp"

#include "live_location/crypto/chacha.hpp"
#include "live_location/crypto/hkdf.hpp"
#include "live_location/crypto/noise.hpp"
#include "live_location/crypto/schnorr.hpp"
#include "live_location/crypto/sha256.hpp"
#include "live_location/encoding/base64.hpp"
#include "live_location/protocol/common.hpp"
#include "live_location/protocol/constants.hpp"

#include <set>
#include <string>

// The pairing scenarios of tools/python/live_location/test_protocol.py, ported.
namespace pairing_tests
{
using namespace live_location;
using namespace live_location_tests;

ByteArray<32> const kLowOrder = HexArray<32>("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800");

// A link holder's forged step 1: it can encrypt like the inviter, but signs with its own key.
nostr::Event MalloryStep1(Invite const & invite, ModelRelay & relay, int64_t now)
{
  auto & rng = ScenarioRng();
  Key const msk = RandomSecpKey(rng);
  noise::HandshakeState hs(true, invite.Prologue(ByteArray<32>{}, ByteArray<32>{}), *invite.m_psk, rng.Get<32>());
  auto const message = hs.WriteMessage(EncodePlaintext(Pair1Json(), kSizeControl));
  nostr::Event ev = PairingEvent(msk, 1, invite, Base64Encode(*message), rng, now);
  relay.Publish(ev);
  return ev;
}

UNIT_TEST(Pairing_CompletesAndChecks)
{
  Pair("Alice", kRelaysA, "Bob", kRelaysB, kT0);
  Pair("Alice", kRelaysA, "Carol", kRelaysB, kT0 + 100);
}

UNIT_TEST(Pairing_Step1RevealsNothing)
{
  auto & rng = ScenarioRng();
  ModelRelay relay;
  Inviter inv(kRelaysA, rng, kT0, 86400);
  std::string const link = inv.GetInvite().Link();
  TEST_EQUAL(inv.GetInvite().Encode().size(), 1 + 32 + 32 + 4 + 1 + (1 + 13) + (1 + 15) + (1 + 22), ("invite layout"));
  auto bob = JoinerStarts(link, "Bob", relay, kT0);
  auto const out = Online(inv, relay, kT0 + 1);
  TEST_EQUAL(out.size(), 1, ());
  nostr::Event const step1 = *out[0].m_publish;
  noise::HandshakeState eve(false, inv.GetInvite().Prologue(bob->Jpk(), bob->C()), *inv.GetInvite().m_psk,
                            rng.Get<32>());
  auto const payload = eve.ReadMessage(*Base64Decode(step1.m_content));
  TEST(payload, ());
  auto const message = DecodePlaintext(*payload);
  TEST(message && MessageType(*message) == "pair1" && message->Get("name") == nullptr,
       ("step 1 reveals nothing to someone holding the invite"));

  // Mallory reads the link and publishes her own step 1. It goes into her own slot (her key), so
  // Alice's step 1 is still there, and Bob, back an hour later, ignores Mallory's.
  nostr::Event const fake = MalloryStep1(*Invite::FromLink(link), relay, kT0 + 2);
  std::set<std::string> const alice = {ToHex(inv.GetInvite().m_ipk)};
  TEST_EQUAL(relay.Query(&alice)[0].m_id, step1.m_id, ("Alice's step 1 cannot be replaced"));
  auto const answered = Online(*bob, relay, kT0 + 3600);
  TEST(answered.size() == 1 && answered[0].m_publish, ("Bob answers the real step 1 and ignores the forged one"));
  Online(inv, relay, kT0 + 3601);
  relay.Publish(*inv.Decide(true, "Alice", kRelaysA, rng, kT0 + 3602).m_publish);
  auto const finished = Online(*bob, relay, kT0 + 3603);
  TEST(finished.size() == 1 && finished[0].m_contact && finished[0].m_contact->m_sas == inv.Sas(),
       ("Bob pairs with the real Alice"));
  TEST(!bob->OnEvent(Wire(fake), rng, kT0 + 3604), ("a forged step 1 is ignored after completion too"));
}

UNIT_TEST(Pairing_ConflictsAbortOrFlag)
{
  auto & rng = ScenarioRng();
  {
    // Mallory as a second joiner while Bob is offline: both apps see both commitments and abort.
    ModelRelay relay;
    Inviter alice(kRelaysA, rng, kT0, 86400);
    std::string const link = alice.GetInvite().Link();
    auto bob = JoinerStarts(link, "Bob", relay, kT0);
    auto mallory = JoinerStarts(link, "Bob", relay, kT0 + 60);
    TEST(Throws<PairingAborted>([&] { Online(alice, relay, kT0 + 120); }), ("the inviter aborts: two joiners"));
    TEST(Throws<PairingAborted>([&] { Online(*bob, relay, kT0 + 180); }), ("the joiner aborts: another joiner"));
    TEST(alice.IsAborted() && !alice.HasSecrets() && bob->IsAborted() && !bob->HasSecrets(),
         ("an abort erases everything"));
  }
  {
    // Mallory first, and Alice connects without comparing codes; Bob opens the link later. Alice's app,
    // still watching until the invite expires, flags the contact; Bob's aborts.
    ModelRelay relay;
    Inviter alice(kRelaysA, rng, kT0, 86400);
    std::string const link = alice.GetInvite().Link();
    auto mallory = JoinerStarts(link, "Bob", relay, kT0);
    Online(alice, relay, kT0 + 1);
    Online(*mallory, relay, kT0 + 2);
    Online(alice, relay, kT0 + 3);
    relay.Publish(*alice.Decide(true, "Alice", kRelaysA, rng, kT0 + 4).m_publish);
    ContactPtr const fakeBob = alice.GetContact();
    auto bob = JoinerStarts(link, "Bob", relay, kT0 + 3600);
    auto const out = Online(alice, relay, kT0 + 3601);
    TEST(out.size() == 1 && out[0].m_flagged && fakeBob->m_flagged,
         ("after pairing, a second joiner flags the contact"));
    TEST(Throws<PairingAborted>([&] { Online(*bob, relay, kT0 + 3602); }), ("the late real joiner aborts"));
  }
  {
    // The same seen from the joiner: after its pairing ended, a later joiner flags the contact.
    Paired p = Pair("Alice", kRelaysA, "Bob", kRelaysB, kT0, false);
    JoinerStarts(p.m_link, "Mallory", *p.m_relay, kT0 + 40);
    auto const j = Online(*p.m_joiner, *p.m_relay, kT0 + 41);
    TEST(j.size() == 1 && j[0].m_flagged && p.m_joinerSide->m_flagged, ("the joiner flags its contact"));
    auto const i = Online(*p.m_inviter, *p.m_relay, kT0 + 41);
    TEST(i.size() == 1 && i[0].m_flagged && p.m_inviterSide->m_flagged, ("the inviter flags its contact too"));
  }
}

UNIT_TEST(Pairing_JunkAndMisdirectedSteps)
{
  auto & rng = ScenarioRng();
  {
    // Without the PSK nothing counts: a step 0 with a wrong MAC is ignored by both sides.
    ModelRelay relay;
    Inviter alice(kRelaysA, rng, kT0);
    auto bob = JoinerStarts(alice.GetInvite().Link(), "Bob", relay, kT0);
    Invite wrong = alice.GetInvite();
    wrong.m_psk = rng.Get<32>();
    Joiner junk(wrong, "X", kRelaysB, rng, kT0);
    relay.Publish(junk.CommitEvent(rng, kT0));
    TEST_EQUAL(Online(alice, relay, kT0 + 1).size(), 1, ("the inviter ignores a step 0 without proof of the PSK"));
    TEST_EQUAL(Online(*bob, relay, kT0 + 2).size(), 1, ("the joiner ignores it too"));
  }
  {
    // A step 1 that answers another joiner's step 0 cannot be decrypted (the prologue binds the
    // accepted step 0): the joiner aborts without revealing its key.
    Inviter alice(kRelaysA, rng, kT0);
    std::string const link = alice.GetInvite().Link();
    Joiner m(*Invite::FromLink(link), "M", kRelaysB, rng, kT0);
    Joiner b(*Invite::FromLink(link), "B", kRelaysB, rng, kT0);
    auto const s1 = alice.OnEvent(Wire(m.CommitEvent(rng, kT0)), rng, kT0);
    TEST(Throws<PairingAborted>([&] { b.OnEvent(Wire(*s1->m_publish), rng, kT0); }) && !b.Step2(),
         ("the joiner aborts on a step 1 meant for someone else, and sends no step 2"));
  }
  {
    // Declining: the joiner learns it and gets no contact.
    ModelRelay relay;
    Inviter alice(kRelaysA, rng, kT0);
    auto dave = JoinerStarts(alice.GetInvite().Link(), "Dave", relay, kT0);
    Online(alice, relay, kT0);
    Online(*dave, relay, kT0);
    Online(alice, relay, kT0);
    auto const d = alice.Decide(false, "Alice", kRelaysA, rng, kT0);
    relay.Publish(*d.m_publish);
    auto const out = Online(*dave, relay, kT0);
    TEST(!d.m_contact && d.m_declined && out.size() == 1 && out[0].m_declined && !out[0].m_contact,
         ("decline: no contact on either side"));
  }
}

// An independent re-implementation of Noise's symmetric state from the primitives, to build messages
// that a correct implementation decrypts but must still refuse.
class MiniNoise
{
public:
  explicit MiniNoise(ByteSpan prologue)
  {
    m_h = crypto::Sha256(AsBytes("Noise_NNpsk0_25519_ChaChaPoly_SHA256"));
    std::copy(m_h.begin(), m_h.end(), m_ck.begin());
    MixHash(prologue);
  }

  void MixHash(ByteSpan data) { m_h = crypto::Sha256Concat({m_h, data}); }

  void MixKey(ByteSpan ikm)
  {
    Key const temp = crypto::HmacSha256(m_ck, ikm);
    uint8_t const one = 1, two = 2;
    Key const o1 = crypto::HmacSha256(temp, ByteSpan(&one, 1));
    m_k = crypto::HmacSha256Concat(temp, {o1, ByteSpan(&two, 1)});
    m_ck = o1;
    m_n = 0;
  }

  void MixKeyAndHash(ByteSpan ikm)
  {
    Key const temp = crypto::HmacSha256(m_ck, ikm);
    uint8_t const one = 1, two = 2, three = 3;
    Key const o1 = crypto::HmacSha256(temp, ByteSpan(&one, 1));
    Key const o2 = crypto::HmacSha256Concat(temp, {o1, ByteSpan(&two, 1)});
    m_k = crypto::HmacSha256Concat(temp, {o2, ByteSpan(&three, 1)});
    m_ck = o1;
    MixHash(o2);
    m_n = 0;
  }

  Bytes EncryptAndHash(ByteSpan plaintext)
  {
    Bytes const ct = crypto::AeadSeal(m_k, Nonce(), m_h, plaintext);
    ++m_n;
    MixHash(ct);
    return ct;
  }

  bool DecryptAndHash(ByteSpan ciphertext)
  {
    bool const ok = crypto::AeadOpen(m_k, Nonce(), m_h, ciphertext).has_value();
    ++m_n;
    MixHash(ciphertext);
    return ok;
  }

private:
  ByteArray<12> Nonce() const
  {
    ByteArray<12> nonce{};
    for (size_t i = 0; i < 8; ++i)
      nonce[4 + i] = static_cast<uint8_t>(m_n >> (8 * i));
    return nonce;
  }

  ByteArray<32> m_h;
  Key m_ck;
  Key m_k;
  uint64_t m_n = 0;
};

Bytes WithLowOrderKey(ByteSpan ciphertext)
{
  Bytes out(kLowOrder.begin(), kLowOrder.end());
  out.insert(out.end(), ciphertext.begin(), ciphertext.end());
  return out;
}

UNIT_TEST(Pairing_LowOrderKeysAbort)
{
  auto & rng = ScenarioRng();
  {
    // A link holder commits to a low-order point and sends a step 2 that is valid under ee = 0, as an
    // unchecked X25519 would accept. Only the all-zero check can refuse it, and the inviter aborts.
    Inviter alice(kRelaysA, rng, kT0);
    Invite const inv = *Invite::FromLink(alice.GetInvite().Link());
    Key const msk = RandomSecpKey(rng);
    auto const mpk = crypto::GetXOnlyPublicKey(msk);
    auto const cLow = Commitment(kLowOrder);
    nostr::Event const s0 = PairingEvent(msk, 0, inv, Step0Content(inv.MacKey(), mpk, cLow), rng, kT0);
    auto const s1 = alice.OnEvent(Wire(s0), rng, kT0);
    TEST(s1 && s1->m_publish, ());
    Bytes const m1 = *Base64Decode(s1->m_publish->m_content);
    MiniNoise mallory(inv.Prologue(mpk, cLow));
    mallory.MixKeyAndHash(*inv.m_psk);
    mallory.MixHash(ByteSpan(m1.data(), 32));
    mallory.MixKey(ByteSpan(m1.data(), 32));
    TEST(mallory.DecryptAndHash(ByteSpan(m1.data() + 32, m1.size() - 32)),
         ("the independent Noise state reads step 1, so it matches"));
    mallory.MixHash(kLowOrder);
    mallory.MixKey(kLowOrder);
    mallory.MixKey(ByteArray<32>{});  // ee = 0
    Bytes const m2 =
        WithLowOrderKey(mallory.EncryptAndHash(EncodePlaintext(ToJson(Pair2{"M", kRelaysB}), kSizeControl)));
    nostr::Event const s2 = PairingEvent(msk, 2, inv, Base64Encode(m2), rng, kT0);
    TEST(Throws<PairingAborted>([&] { alice.OnEvent(Wire(s2), rng, kT0); }), ("all-zero ee aborts the pairing"));
  }
  {
    // The joiner's side: a step 1 (only the real inviter can sign one) whose ephemeral key is a
    // low-order point. It decrypts, since message 1 needs no DH; writing step 2 computes ee, and that
    // must abort the pairing rather than escape as an error.
    Inviter alice(kRelaysA, rng, kT0);
    Joiner bob(*Invite::FromLink(alice.GetInvite().Link()), "Bob", kRelaysB, rng, kT0);
    Bytes const prologue = alice.GetInvite().Prologue(bob.Jpk(), bob.C());
    Key const psk = *alice.GetInvite().m_psk;
    MiniNoise attacker(prologue);
    attacker.MixKeyAndHash(psk);
    attacker.MixHash(kLowOrder);
    attacker.MixKey(kLowOrder);
    Bytes const m1 = WithLowOrderKey(attacker.EncryptAndHash(EncodePlaintext(Pair1Json(), kSizeControl)));

    noise::HandshakeState probe(false, prologue, psk, rng.Get<32>());
    TEST(probe.ReadMessage(m1).has_value() && !probe.WriteMessage(AsBytes("x")),
         ("the message decrypts, and only ee fails"));
    nostr::Event const s1 =
        PairingEvent(alice.PairingSecretForVectors(), 1, alice.GetInvite(), Base64Encode(m1), rng, kT0);
    TEST(Throws<PairingAborted>([&] { bob.OnEvent(Wire(s1), rng, kT0); }) && !bob.Step2() && !bob.HasSecrets() &&
             bob.IsAborted(),
         ("the joiner aborts on a low-order key in step 1, sends no step 2 and erases everything"));
  }
}
}  // namespace pairing_tests
