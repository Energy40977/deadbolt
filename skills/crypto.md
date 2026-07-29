# Lens: crypto — Breaking Cryptographic Controls

## Mandate

Cryptography rarely fails because of the algorithm — it fails because of **key
management and usage mistakes**. Find the point that can be broken.

## Phase 1 — Cryptographic Inventory

```
Grep: "encrypt|decrypt|cipher|AES|GCM|ChaCha|hmac|hashlib|bcrypt|argon|scrypt"
Grep: "jwt|jws|jwe|sign|verify|token|secret_key|private_key|kek|dek"
Grep: "random|urandom|secrets\.|SecureRandom|crypto\."
```

For every use, establish: **what is protected · with which key · where the key comes from**

## Phase 2 — Attack Tree

### A. Obtaining The Key

```
Grep: "key\s*=\s*['\"]|KEY\s*=\s*['\"]|Buffer\.from\(['\"]|bytes\.fromhex\(['\"]"
```

If the key is a literal in the code, everyone with repository access — a former
employee, the owner of a fork, a CI log — can decrypt the data. **Git history is
forever.**

If the key comes from an environment variable: is there a default? A default
value is a hardcoded key.

### B. Nonce Or IV Reuse — Key Recovery Under GCM

```
Grep: "nonce\s*=|iv\s*=|initialization_vector|IvParameterSpec"
```

**Critical:** reusing a nonce with the same key under AES-GCM allows **key
recovery** (the forbidden attack). Look for fixed nonces and counter resets.

How it breaks: two ciphertexts under the same nonce, XOR them, and both the
plaintext and the authentication key fall out.

### C. Unauthenticated Encryption — Oracle Attacks

ECB leaks structure. CBC without a MAC allows plaintext recovery through a
padding oracle.

```
Grep: "MODE_ECB|MODE_CBC|AES/CBC|NoPadding|PKCS5Padding"
```

If the MAC is computed separately: is the order **encrypt-then-MAC**?

### D. Password Cracking

```
Grep: "password" -> then read the function next to it
```

SHA-256 or MD5 means billions of guesses per second on a GPU. Argon2id, bcrypt or
scrypt makes it impractical. Argon2 parameters: `memory_cost` >= 64 MiB,
`time_cost` >= 3.

Is the salt unique per password? A fixed salt means rainbow tables work.

### E. Breaking JWT

```
Grep: "jwt\.|decode\(|verify\(|algorithms|alg"
```

Check, in order:
1. Is `alg: none` accepted? That is an unsigned token
2. Is the algorithm **pinned server-side**, or read from the token? RS256-to-HS256
   confusion lets an attacker forge tokens using the public key as the HMAC secret
3. Is `exp` verified? Otherwise tokens live forever
4. Are `aud` and `iss` verified? Otherwise another service's token is accepted
5. How long is the lifetime? Are refresh tokens rotated?

### F. Timing Attack

```
Grep: "==\s*(signature|token|hmac|digest|secret)|secret\s*=="
```

Ordinary equality stops at the first differing byte, so comparison time reveals
the secret character by character. `hmac.compare_digest`, `timingSafeEqual` or
`subtle.ConstantTimeCompare` is required.

### G. Predictable Token

```
Grep: "random\.|Math\.random|mt_rand|new Random|time\(\)|uuid1"
```

The state of a Mersenne Twister can be recovered from 624 outputs, which makes
future tokens computable. `uuid1` is based on time plus MAC address, so it is
predictable.

### H. Token Stored In The Clear

If the `token` column holds plaintext, a database leak hands over every active
session. Store a hash instead.

### I. No Way To Rotate

If the key encrypts the data directly (no envelope scheme), rotation requires
re-encrypting everything — which in practice means it **never happens**.

## Phase 3 — Verification

- [ ] The code path is really used (not dead code)
- [ ] The key and nonce sources have been traced
- [ ] The library's default behaviour was checked (some libraries generate the nonce themselves)

## False-Positive Traps

| Trap | Check |
|---|---|
| The library generates the nonce automatically | Check the API documentation or signature |
| MD5 is only used for a cache key | Look for `usedforsecurity=False`, read the context |
| `random` is used for animation or jitter | Read the call site |
| The key is a test fixture | Check the path |
| The JWT library pins `alg` by default | Check the behaviour of that version |
