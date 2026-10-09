# External test vectors

Published third-party vectors used to check the primitives under `../../nll/`.

| File | Origin | License | SHA-256 of source |
|---|---|---|---|
| `bip340-test-vectors.csv` | [bitcoin/bips `bip-0340/test-vectors.csv`](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv) (repo HEAD `927b6de9915c` on 2026-10-09) | BSD-2-Clause (BIP-340 header) | `34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d` (upstream, CRLF line endings); the copy here is LF-normalised by `.gitattributes`: `01c8cabba63b4c9b2f44c975902990086a4fe56eee9d265b187d1e2c1d98ccfb` |
| `noise_NNpsk0_25519_ChaChaPoly_SHA256.json` | The single `Noise_NNpsk0_25519_ChaChaPoly_SHA256` entry of [cacophony `vectors/cacophony.txt`](https://github.com/haskell-cryptography/cacophony/blob/master/vectors/cacophony.txt) (repo HEAD `8ee9d41e34a1`) | Public domain (Unlicense) | `3bde7c09a6f349ee11c825c50fcc02649f8f02a47c857a459206b357f9386cae` (whole `cacophony.txt`) |

Not vendored (license of the file is not stated): the NIP-44 v2 vectors. `test_primitives.py` downloads
[`nip44.vectors.json`](https://raw.githubusercontent.com/paulmillr/nip44/main/nip44.vectors.json) on first use and
refuses it unless its SHA-256 equals the checksum published in NIP-44 itself:
`269ed0f69e4c192512cc779e78c555090cebc7c785b609e338a62afc3ce25040`.
