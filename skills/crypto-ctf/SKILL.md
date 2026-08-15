name: crypto-ctf
description: CTF cryptography solving methodology — recognize the encoding/cipher from the ciphertext shape, then apply the matching attack: base64/hex/rot, classical ciphers (Caesar/Vigenere/Atbash), XOR key recovery, and the common modern primitives (RSA/ECC/AES). Covers the tool-first workflow (CyberChef/dcode/RsaCtfTool) and known-plaintext/crib techniques. Use on any crypto/misc challenge.
---

# CTF Crypto Solving

Authorized CTF/assessment use. Crypto challenges are "recognize the scheme → apply the attack". The win is identification, not manual math — use tools first, write the solver only when you know the scheme.

## 1. Identify the scheme from the ciphertext shape

| Shape | Likely scheme |
|---|---|
| `base64`, `hex`, `=`/`==` padding, printable | encoding (base64/32/58/hex/rot13/url) |
| letters only, preserved case, ~26 shift | Caesar / rotN |
| letters only, repeated key pattern | Vigenere |
| reversed / mirrored alphabet | Atbash |
| digits grouped 2-3 | Polybius square |
| long hex/base64 + numbers, `N=e` hints | RSA |
| `flag` known prefix + same length | XOR / stream cipher (crib attack) |
| weird symbols / bar patterns | Braille / Morse / semaphore |

## 2. Tool-first workflow

1. **CyberChef** / **dcode.fr** — paste and try "Magic" / auto-detect before writing anything.
2. Decode nested encodings repeatedly (base64 → hex → rot13 → ...) — crypto flags are often triple-wrapped.
3. `strings`, `file` on any provided file; check for a hidden key/IV/nonce in the file or filename.

## 3. The big three attack families

**Classical (letters):**
- Caesar/rot: brute all 26 shifts, look for `flag{`.
- Vigenere: recover the key length via Kasiski/Friedman, then frequency-analysis each column; or crib-drag a known `flag{`.
- Substitution: frequency analysis on the ciphertext against English letter frequencies.

**XOR (the most common):**
- Single-byte: brute the 0-255 key, score plaintext for printable/`flag`.
- Multi-byte key: guess key length, brute each key byte with frequency scoring.
- **Known-plaintext crib:** `cipher XOR "flag{"` recovers the key start → extend the key by known structure.

**RSA / modern:**
- Common primes / small-e: if the same `n` is reused or `e` is small with a short plaintext, use **RsaCtfTool** / Wiener / Coppersmith attacks.
- AES: if key/IV are recoverable (XOR, leak, weak KDF), just decrypt; otherwise it's usually misdirection — the flag is elsewhere.

## 4. Practical cribbing

```
# XOR crib-drag: known plaintext reveals key
key_bytes = cipher[:5] XOR b"flag{"
# then extend by guessing the next chars
```
```
# Vigenere / repeating XOR key-length check
# identical repeated ciphertext blocks / Kasiski distance → key length
```

## Cross-cutting
- **Identify before computing** — 80% of crypto is recognizing base64/XOR/Caesar; the solver is trivial once you know.
- **Decode layers exhaustively** — nested encodings are the default, not the exception.
- **`flag{` is a free crib** — every XOR/stream/classical attack should crib-drag the known prefix first.
