#include "testing/testing.hpp"

#include "live_location/live_location_tests/test_helpers.hpp"

#include "live_location/crypto/chacha.hpp"
#include "live_location/crypto/hkdf.hpp"
#include "live_location/crypto/nip44.hpp"
#include "live_location/crypto/noise.hpp"
#include "live_location/crypto/random.hpp"
#include "live_location/crypto/schnorr.hpp"
#include "live_location/crypto/sha256.hpp"
#include "live_location/crypto/x25519.hpp"
#include "live_location/encoding/base64.hpp"

#include "cppjansson/cppjansson.hpp"

#include "base/logging.hpp"

#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace crypto_tests
{
using namespace live_location;
using namespace live_location::crypto;
using namespace live_location_tests;

std::string_view constexpr kSunscreen =
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be "
    "it.";

std::string JsonString(json_t const * root, char const * field)
{
  return FromJSONObject<std::string>(root, field);
}

// TEST_THROW pastes its exception argument after "std::", so it takes unqualified standard names.
using std::invalid_argument;
using std::logic_error;

UNIT_TEST(Sha256_Nist)
{
  TEST_EQUAL(ToHex(Sha256(AsBytes(""))), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ());
  TEST_EQUAL(ToHex(Sha256(AsBytes("abc"))), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", ());
  std::string_view const m448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  TEST_EQUAL(ToHex(Sha256(AsBytes(m448))), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", ());
  TEST_EQUAL(ToHex(Sha256Concat({AsBytes(m448.substr(0, 13)), AsBytes(m448.substr(13))})), ToHex(Sha256(AsBytes(m448))),
             ());
}

UNIT_TEST(HmacSha256_Rfc4231)
{
  TEST_EQUAL(ToHex(HmacSha256(Bytes(20, 0x0b), AsBytes("Hi There"))),
             "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", ());
  TEST_EQUAL(ToHex(HmacSha256(AsBytes("Jefe"), AsBytes("what do ya want for nothing?"))),
             "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", ());
  // A key longer than the block size is hashed first.
  TEST_EQUAL(ToHex(HmacSha256(Bytes(131, 0xaa), AsBytes("Test Using Larger Than Block-Size Key - Hash Key First"))),
             "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", ());
}

UNIT_TEST(Hkdf_Rfc5869)
{
  auto const range = [](uint8_t from, uint8_t to)
  {
    Bytes out;
    for (unsigned b = from; b <= to; ++b)
      out.push_back(static_cast<uint8_t>(b));
    return out;
  };

  auto prk = HkdfExtract(Hex("000102030405060708090a0b0c"), Bytes(22, 0x0b));
  TEST_EQUAL(ToHex(prk), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", ());
  TEST_EQUAL(ToHex(HkdfExpand(prk, Hex("f0f1f2f3f4f5f6f7f8f9"), 42)),
             "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", ());

  prk = HkdfExtract(range(0x60, 0xaf), range(0x00, 0x4f));
  TEST_EQUAL(ToHex(prk), "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244", ());
  TEST_EQUAL(
      ToHex(HkdfExpand(prk, range(0xb0, 0xff), 82)),
      "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c"
      "2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
      ());

  prk = HkdfExtract(ByteSpan(), Bytes(22, 0x0b));
  TEST_EQUAL(ToHex(prk), "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04", ());
  TEST_EQUAL(ToHex(HkdfExpand(prk, ByteSpan(), 42)),
             "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8", ());

  TEST_THROW(HkdfExpand(Bytes(31, 1), ByteSpan(), 32), invalid_argument, ());
  TEST_THROW(HkdfExpand(prk, ByteSpan(), 255 * 32 + 1), invalid_argument, ());
  TEST_EQUAL(HkdfExpand(prk, ByteSpan(), 255 * 32).size(), 255 * 32, ());
}

UNIT_TEST(ChaCha20_Rfc8439)
{
  Bytes key;
  for (uint8_t b = 0; b < 32; ++b)
    key.push_back(b);
  TEST_EQUAL(
      ToHex(ChaCha20(key, Hex("000000000000004a00000000"), AsBytes(kSunscreen), 1)),
      "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e6"
      "5152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8"
      "eedf2785e42874d",
      ());
  TEST_THROW(ChaCha20(key, Bytes(8), AsBytes("x")), invalid_argument, ());
}

UNIT_TEST(ChaChaPoly_Rfc8439)
{
  Bytes key;
  for (unsigned b = 0x80; b < 0xa0; ++b)
    key.push_back(static_cast<uint8_t>(b));
  auto const nonce = Hex("070000004041424344454647");
  auto const ad = Hex("50515253c0c1c2c3c4c5c6c7");
  auto const sealed = AeadSeal(key, nonce, ad, AsBytes(kSunscreen));
  TEST_EQUAL(
      ToHex(sealed),
      "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e"
      "060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576"
      "d26586cec64b6116"
      "1ae10b594f09e26a7e902ecbd0600691",
      ());
  auto const opened = AeadOpen(key, nonce, ad, sealed);
  TEST(opened, ());
  TEST_EQUAL(std::string(opened->begin(), opened->end()), kSunscreen, ());

  auto tampered = sealed;
  tampered.back() ^= 1;
  TEST(!AeadOpen(key, nonce, ad, tampered), ());
  TEST(!AeadOpen(key, nonce, Hex("50515253c0c1c2c3c4c5c6c8"), sealed), ());
  TEST(!AeadOpen(key, nonce, ad, ByteSpan(sealed.data(), 15)), ());
}

UNIT_TEST(X25519_Rfc7748)
{
  auto const alice = HexKey("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
  auto const bob = HexKey("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
  auto const alicePub = X25519PublicKey(alice);
  auto const bobPub = X25519PublicKey(bob);
  TEST_EQUAL(ToHex(alicePub), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", ());
  TEST_EQUAL(ToHex(bobPub), "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", ());
  auto const shared1 = X25519(alice, bobPub);
  auto const shared2 = X25519(bob, alicePub);
  TEST(shared1 && shared2, ());
  TEST_EQUAL(ToHex(*shared1), "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", ());
  TEST_EQUAL(ToHex(*shared1), ToHex(*shared2), ());

  // A low-order point gives an all-zero result, which NLL treats as an abort (spec §3).
  TEST(!X25519(alice, Hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")), ());
  TEST(!X25519(alice, Bytes(32, 0)), ());
}

UNIT_TEST(Bip340_PublishedVectors)
{
  std::istringstream csv(ReadFile(VectorsPath("external/bip340-test-vectors.csv")));
  std::string line;
  TEST(std::getline(csv, line), ("bip340-test-vectors.csv is missing"));
  size_t rows = 0;
  size_t signs = 0;
  while (std::getline(csv, line))
  {
    if (line.empty())
      continue;
    // index, secret key, public key, aux_rand, message, signature, verification result, comment
    std::vector<std::string> fields;
    std::istringstream row(line);
    std::string field;
    while (fields.size() < 7 && std::getline(row, field, ','))
      fields.push_back(field);
    TEST_EQUAL(fields.size(), 7, (line));
    auto const pub = Hex(fields[2]);
    auto const message = Hex(fields[4]);
    auto const sig = Hex(fields[5]);
    bool const expected = fields[6] == "TRUE";
    if (!fields[1].empty())
    {
      auto const sk = HexKey(fields[1]);
      TEST(IsValidSecretKey(sk), (fields[0]));
      TEST_EQUAL(ToHex(GetXOnlyPublicKey(sk)), ToHex(pub), (fields[0]));
      // Nostr event ids are always 32 bytes, so only 32-byte messages are signed.
      if (message.size() == 32)
      {
        auto const aux = HexArray<32>(fields[3]);
        TEST_EQUAL(ToHex(SchnorrSign(sk, HexArray<32>(fields[4]), aux)), ToHex(sig), (fields[0]));
        ++signs;
      }
    }
    TEST_EQUAL(SchnorrVerify(pub, message, sig), expected, (fields[0], fields.size() > 7 ? fields[7] : ""));
    ++rows;
  }
  TEST_EQUAL(rows, 19, ());
  TEST_GREATER(signs, 3, ());

  TEST(!IsValidSecretKey(Bytes(32, 0)), ());
  TEST(!IsValidSecretKey(Hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")), ("n itself"));
  TEST(IsValidSecretKey(Hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")), ("n - 1"));
  TEST(!IsValidXOnlyPublicKey(Bytes(32, 0)), ());
  TEST(!IsValidXOnlyPublicKey(Bytes(31, 1)), ());
  TEST_THROW(GetXOnlyPublicKey(Key()), invalid_argument, ());
}

UNIT_TEST(Noise_CacophonyVector)
{
  base::Json const json(ReadFile(VectorsPath("external/noise_NNpsk0_25519_ChaChaPoly_SHA256.json")));
  json_t const * root = json.get();
  TEST_EQUAL(JsonString(root, "protocol_name"), "Noise_NNpsk0_25519_ChaChaPoly_SHA256", ());

  auto const psk = [&](char const * field)
  {
    json_t const * psks = base::GetJSONObligatoryField(root, field);
    std::string hex;
    FromJSON(json_array_get(psks, 0), hex);
    return HexKey(hex);
  };
  noise::HandshakeState init(true /* initiator */, Hex(JsonString(root, "init_prologue")), psk("init_psks"),
                             HexKey(JsonString(root, "init_ephemeral")));
  noise::HandshakeState resp(false /* initiator */, Hex(JsonString(root, "resp_prologue")), psk("resp_psks"),
                             HexKey(JsonString(root, "resp_ephemeral")));

  json_t const * messages = base::GetJSONObligatoryField(root, "messages");
  size_t const count = json_array_size(messages);
  TEST_GREATER(count, 2, ());
  auto const payload = [&](size_t i) { return Hex(JsonString(json_array_get(messages, i), "payload")); };
  auto const ciphertext = [&](size_t i) { return JsonString(json_array_get(messages, i), "ciphertext"); };

  TEST_THROW(resp.WriteMessage(payload(0)), logic_error, ("the responder does not speak first"));
  auto const m0 = init.WriteMessage(payload(0));
  TEST(m0, ());
  TEST_EQUAL(ToHex(*m0), ciphertext(0), ());
  auto const r0 = resp.ReadMessage(*m0);
  TEST(r0, ());
  TEST_EQUAL(ToHex(*r0), ToHex(payload(0)), ());

  auto const m1 = resp.WriteMessage(payload(1));
  TEST(m1, ());
  TEST_EQUAL(ToHex(*m1), ciphertext(1), ());
  auto const r1 = init.ReadMessage(*m1);
  TEST(r1, ());
  TEST_EQUAL(ToHex(*r1), ToHex(payload(1)), ());

  TEST(init.IsComplete() && resp.IsComplete(), ());
  TEST_EQUAL(ToHex(init.HandshakeHash()), JsonString(root, "handshake_hash"), ());
  TEST_EQUAL(ToHex(resp.HandshakeHash()), JsonString(root, "handshake_hash"), ());

  auto const initKeys = init.Split();
  auto const respKeys = resp.Split();
  TEST_EQUAL(ToHex(initKeys.m_k1), ToHex(respKeys.m_k1), ());
  TEST_EQUAL(ToHex(initKeys.m_k2), ToHex(respKeys.m_k2), ());
  noise::CipherState ic1(initKeys.m_k1), ic2(initKeys.m_k2), rc1(respKeys.m_k1), rc2(respKeys.m_k2);
  for (size_t i = 2; i < count; ++i)
  {
    bool const fromInitiator = i % 2 == 0;
    auto const ct = (fromInitiator ? ic1 : rc2).EncryptWithAd(ByteSpan(), payload(i));
    TEST_EQUAL(ToHex(ct), ciphertext(i), (i));
    auto const pt = (fromInitiator ? rc1 : ic2).DecryptWithAd(ByteSpan(), ct);
    TEST(pt, (i));
    TEST_EQUAL(ToHex(*pt), ToHex(payload(i)), (i));
  }
}

UNIT_TEST(Noise_TamperedAndLowOrderMessagesFail)
{
  auto const psk = HexKey("54686973206973206d7920417573747269616e20706572737065637469766521");
  auto const prologue = AsBytes("prologue");
  noise::HandshakeState init(true, prologue, psk, HexKey(std::string(64, '1')));
  noise::HandshakeState resp(false, prologue, psk, HexKey(std::string(64, '2')));
  auto m0 = init.WriteMessage(AsBytes("hello"));
  TEST(m0, ());
  auto bad = *m0;
  bad.back() ^= 1;
  TEST(!resp.ReadMessage(bad), ("a tampered message does not decrypt"));

  noise::HandshakeState wrongPsk(false, prologue, HexKey(std::string(64, '3')), HexKey(std::string(64, '2')));
  TEST(!wrongPsk.ReadMessage(*m0), ("a different PSK does not decrypt"));
  noise::HandshakeState wrongPrologue(false, AsBytes("other"), psk, HexKey(std::string(64, '2')));
  TEST(!wrongPrologue.ReadMessage(*m0), ("a different prologue does not decrypt"));

  // The low-order messages below were built with the Python reference (nll/noise.py), which a
  // low-order key needs: no secret key has one as its public key.
  TEST_EQUAL(ToHex(*m0),
             "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13b1031001fce4926c0447e18ce7f0c4d45f6734b37"
             "1",
             ("matches the Python reference"));

  // Message 0 with a low-order ephemeral key decrypts (it needs no DH), but the responder's ee is then
  // all zeros, so it refuses to write message 1 rather than continue under a key from the PSK alone.
  noise::HandshakeState resp2(false, prologue, psk, HexKey(std::string(64, '2')));
  auto const m0Low =
      Hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b80032d37a70c7993dafc8e866e3838267da5dfebd8e8e");
  auto const hello = resp2.ReadMessage(m0Low);
  TEST(hello && std::string(hello->begin(), hello->end()) == "hello", ());
  TEST(!resp2.WriteMessage(AsBytes("reply")), ("all-zero ee when writing"));

  // Message 1 with a low-order ephemeral key: the initiator's ee is all zeros, and it refuses it.
  auto const m1Low =
      Hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800b1af6b604a644677ea0228498fc87fa7aeb7c1fdff");
  TEST(!init.ReadMessage(m1Low), ("all-zero ee when reading"));
}

UNIT_TEST(Nip44_PublishedVectors)
{
  // Downloaded on first use by tools/python/live_location/test_primitives.py, which pins its checksum
  // (vectors/external/SOURCES.md says why the file is not vendored).
  std::string const data = ReadFile(VectorsPath("cache/nip44.vectors.json"));
  if (data.empty())
  {
    LOG(LWARNING, ("Skipped: run tools/python/live_location/test_primitives.py once to fetch nip44.vectors.json"));
    return;
  }
  TEST_EQUAL(ToHex(Sha256(AsBytes(data))), "269ed0f69e4c192512cc779e78c555090cebc7c785b609e338a62afc3ce25040",
             ("checksum published in NIP-44"));
  base::Json const json(data);
  json_t const * v2 = base::GetJSONObligatoryField(json.get(), "v2");
  json_t const * valid = base::GetJSONObligatoryField(v2, "valid");
  json_t const * invalid = base::GetJSONObligatoryField(v2, "invalid");

  json_t const * mk = base::GetJSONObligatoryField(valid, "get_message_keys");
  auto const mkConversationKey = HexKey(JsonString(mk, "conversation_key"));
  json_t const * keys = base::GetJSONObligatoryField(mk, "keys");
  for (size_t i = 0; i < json_array_size(keys); ++i)
  {
    json_t const * t = json_array_get(keys, i);
    auto const out = nip44::GetMessageKeys(mkConversationKey, HexArray<32>(JsonString(t, "nonce")));
    TEST_EQUAL(ToHex(out.m_chachaKey), JsonString(t, "chacha_key"), (i));
    TEST_EQUAL(ToHex(out.m_chachaNonce), JsonString(t, "chacha_nonce"), (i));
    TEST_EQUAL(ToHex(out.m_hmacKey), JsonString(t, "hmac_key"), (i));
  }

  json_t const * padded = base::GetJSONObligatoryField(valid, "calc_padded_len");
  for (size_t i = 0; i < json_array_size(padded); ++i)
  {
    json_t const * t = json_array_get(padded, i);
    size_t const in = json_integer_value(json_array_get(t, 0));
    size_t const out = json_integer_value(json_array_get(t, 1));
    TEST_EQUAL(nip44::CalcPaddedLen(in), out, (in));
  }

  json_t const * ed = base::GetJSONObligatoryField(valid, "encrypt_decrypt");
  for (size_t i = 0; i < json_array_size(ed); ++i)
  {
    json_t const * t = json_array_get(ed, i);
    // The conversation key is given: NLL never derives one by ECDH, so libsecp256k1 is built
    // without that module and the get_conversation_key vectors do not apply.
    auto const ck = HexKey(JsonString(t, "conversation_key"));
    std::string const plaintext = JsonString(t, "plaintext");
    auto const payload = nip44::Encrypt(AsBytes(plaintext), ck, HexArray<32>(JsonString(t, "nonce")));
    TEST_EQUAL(payload, JsonString(t, "payload"), (i));
    auto const decrypted = nip44::Decrypt(payload, ck);
    TEST(decrypted, (i));
    TEST_EQUAL(std::string(decrypted->begin(), decrypted->end()), plaintext, (i));
  }

  json_t const * longMsgs = base::GetJSONObligatoryField(valid, "encrypt_decrypt_long_msg");
  for (size_t i = 0; i < json_array_size(longMsgs); ++i)
  {
    json_t const * t = json_array_get(longMsgs, i);
    std::string plaintext;
    std::string const pattern = JsonString(t, "pattern");
    for (json_int_t r = json_integer_value(base::GetJSONObligatoryField(t, "repeat")); r > 0; --r)
      plaintext += pattern;
    TEST_EQUAL(ToHex(Sha256(AsBytes(plaintext))), JsonString(t, "plaintext_sha256"), (i));
    auto const ck = HexKey(JsonString(t, "conversation_key"));
    auto const payload = nip44::Encrypt(AsBytes(plaintext), ck, HexArray<32>(JsonString(t, "nonce")));
    TEST_EQUAL(ToHex(Sha256(AsBytes(payload))), JsonString(t, "payload_sha256"), (i));
    auto const decrypted = nip44::Decrypt(payload, ck);
    TEST(decrypted && decrypted->size() == plaintext.size(), (i));
  }

  // The vector file predates the extended-length amendment: the NLL profile refuses all of these.
  json_t const * lengths = base::GetJSONObligatoryField(invalid, "encrypt_msg_lengths");
  for (size_t i = 0; i < json_array_size(lengths); ++i)
  {
    size_t const n = json_integer_value(json_array_get(lengths, i));
    TEST_THROW(nip44::Encrypt(Bytes(n, 'a'), mkConversationKey, ByteArray<32>{}), invalid_argument, (n));
  }

  json_t const * badDecrypt = base::GetJSONObligatoryField(invalid, "decrypt");
  for (size_t i = 0; i < json_array_size(badDecrypt); ++i)
  {
    json_t const * t = json_array_get(badDecrypt, i);
    TEST(!nip44::Decrypt(JsonString(t, "payload"), HexKey(JsonString(t, "conversation_key"))), (JsonString(t, "note")));
  }
}

UNIT_TEST(Nip44_ProfileAndTampering)
{
  auto const ck = HexKey("c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d");
  ByteArray<32> nonce{};
  nonce[31] = 1;
  std::string const text(512, ' ');
  auto const payload = nip44::Encrypt(AsBytes(text), ck, nonce);
  auto const back = nip44::Decrypt(payload, ck);
  TEST(back && back->size() == 512, ());

  auto wrongKey = ck;
  wrongKey[0] ^= 1;
  TEST(!nip44::Decrypt(payload, wrongKey), ());
  std::string flipped = payload;
  flipped[60] = flipped[60] == 'A' ? 'B' : 'A';
  TEST(!nip44::Decrypt(flipped, ck), ());
  TEST(!nip44::Decrypt(payload.substr(0, payload.size() - 4), ck), ());
  TEST(!nip44::Decrypt("#" + payload.substr(1), ck), ());
  TEST_THROW(nip44::Encrypt(Bytes(), ck, nonce), invalid_argument, ());
  TEST_THROW(nip44::Encrypt(Bytes(65536, 'a'), ck, nonce), invalid_argument, ());
  TEST_EQUAL(nip44::Encrypt(Bytes(65535, 'a'), ck, nonce).empty(), false, ());
}

UNIT_TEST(Base64_Strict)
{
  // The same cases as the Python reference (test_protocol.py).
  TEST(!Base64Decode("AB=="), ("non-zero unused bits"));
  TEST(!Base64Decode("AA"), ("missing padding"));
  TEST(Base64Decode("AA==") == Bytes{0}, ());
  TEST(Base64Decode("") == Bytes{}, ());
  TEST(!Base64Decode("AA=A"), ());
  TEST(!Base64Decode("A==="), ());
  TEST(!Base64Decode("AAAA===="), ());
  TEST(!Base64Decode("AA==\n"), ());
  TEST(!Base64Decode("A-=="), ("the URL-safe alphabet is not base64"));
  TEST(!Base64UrlDecode("AB"), ("non-zero unused bits"));
  TEST(Base64UrlDecode("AA") == Bytes{0}, ());
  TEST(!Base64UrlDecode("AA=="), ("no padding in base64url"));
  TEST(!Base64UrlDecode("A"), ());
  TEST(!Base64UrlDecode("AA+A"), ());

  TestRng rng(AsBytes("base64"));
  for (size_t n = 0; n < 40; ++n)
  {
    auto const data = rng.GetBytes(n);
    TEST(Base64Decode(Base64Encode(data)) == data, (n));
    TEST(Base64UrlDecode(Base64UrlEncode(data)) == data, (n));
    TEST_EQUAL(Base64UrlEncode(data).find('='), std::string::npos, (n));
  }
  TEST_EQUAL(Base64Encode(Hex("fbff")), "+/8=", ());
  TEST_EQUAL(Base64UrlEncode(Hex("fbff")), "-_8", ());
}

UNIT_TEST(TestRng_MatchesPythonReference)
{
  // Output of TestRng(b'cpp-test') in tools/python/live_location/nll/protocol.py.
  TestRng rng(AsBytes("cpp-test"));
  TEST_EQUAL(ToHex(rng.GetBytes(16)), "531b66adc7f8ceee94b4c195895a5b6c", ());
  TEST_EQUAL(ToHex(rng.GetBytes(40)),
             "4b172a8cd0c6a361bd77b10ae48919b7144183bc73319b339995ce15217dc9b25ec7a8a260f0f85c", ());

  auto const a = SystemRng().GetBytes(32);
  auto const b = SystemRng().GetBytes(32);
  TEST_NOT_EQUAL(a, b, ());
}

UNIT_TEST(Bytes_HexAndCompare)
{
  TEST(!FromHex("0"), ());
  TEST(!FromHex("0G"), ());
  TEST(!FromHex("AB"), ("uppercase is not accepted where the spec says lowercase"));
  TEST(FromHex("00ff") == (Bytes{0, 255}), ());
  TEST(ConstantTimeEqual(Hex("0102"), Hex("0102")), ());
  TEST(!ConstantTimeEqual(Hex("0102"), Hex("0103")), ());
  TEST(!ConstantTimeEqual(Hex("0102"), Hex("010200")), ());
}
}  // namespace crypto_tests
