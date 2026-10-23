<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Cryptography and keys

What the app hashes, encrypts and generates, with which key, and for how long the results live.

## Key policy

- **One root key.** Every key of the app is derived from the instance `secret` in `config.php`. The app stores no key of its own, in the database or anywhere else. A database dump alone is not enough to test guesses against a stored fingerprint.
- **One key per purpose.** `Crypto\Fingerprinter` derives each key as `HMAC-SHA256(secret, "intrusion_detection/" + purpose)` and keeps it in memory for one request only. All keyed hashing of the app goes through this one class.
- **No secret, no fingerprint.** Without a `secret` the app refuses to fingerprint instead of hashing without a key.
- **Encryption is core's.** The app encrypts nothing itself. Where it needs encryption, it uses core's `ICrypto` (AES-256-CBC with a random IV and HMAC-SHA512, encrypt-then-MAC), whose key also comes from the instance secret.
- **Randomness is core's.** Every secret the app makes comes from core's `ISecureRandom`.
- **Secrets are compared in constant time** (`hash_equals`), or verified with core's `IHasher`.

## Inventory

| What | How | Key | Stored where, how long |
| --- | --- | --- | --- |
| Password of a failed login | HMAC-SHA256, first 16 bytes | `password/<UTC day>`, changes daily | Failed attempts, 1 hour; flags of sprayed passwords, at most 1 day |
| Login name, reset input | HMAC-SHA256 of the lower-cased, trimmed value, 16 bytes | `name` | Failed attempts, 1 hour |
| Share token of a failed share access | HMAC-SHA256, 16 bytes | `share_token` | Failed attempts, 1 hour |
| Credential of a request (session or app password) | HMAC-SHA256, 12 bytes, base64url | `credential/<UTC day>` | Memory cache only, about an hour |
| Decoy secret | HMAC-SHA256, 32 bytes | `decoy` | Decoys, until deleted |
| Remembered-device id from the cookie | HMAC-SHA256, 32 bytes | `device` | Known devices, 180 days after last use |
| Session id of an unconfirmed or refused login | SHA-256 without a key, 16 bytes as hex; a session id is long and random, and a new `secret` must not let the login back in | — | Unconfirmed logins, until confirmed or ended |
| Lock-link token | HMAC-SHA256 as hex | `lock_link` | Lock links, 7 days |
| Value of a watched setting | HMAC-SHA256 as hex | `setting` | Settings snapshot, replaced at every check |
| Accounts, email addresses and IP addresses in memory-cache keys, and the merge key of a detection | HMAC-SHA256 as hex | `lookup` | Memory cache, minutes to a day; detections, with the detection |
| Previous email address after a change | core `ICrypto` | instance secret | Security changes, 1 day |
| Cached Pwned Passwords range | core `ICrypto`; cache key is core's `calculateHMAC` of the prefix | instance secret | Memory cache, 1 day |
| Email confirmation code (6 digits) | core `IHasher` | — | The login's session state, 10 minutes |

Secrets the app generates with `ISecureRandom`: lock-link tokens (43 letters and digits), remembered-device ids (43 characters), the lock page nonce (32 letters and digits), decoy secrets, and email codes (6 digits; valid 10 minutes, 5 tries, at most 5 emails an hour per account).

Hashes that protect nothing: SHA-1 of a password for the Pwned Passwords range API (only the first 5 hex characters are sent), MD5 for lock names in the memory cache, CRC32 as a short tag of a login name in the memory cache, and SHA-256 for ids of custom signatures and of the firewall export state.

## Lifetime and rotation

- The password and credential keys change at UTC midnight. A stored password fingerprint can therefore only be linked to attempts of the same day; in the first hour after midnight the previous day's key is tried too.
- The other keys change only with the instance `secret`. Changing the `secret` makes every value in the table above that was made with the old key unusable: decoy secrets no longer match, remembered devices are forgotten, open lock links stop working, and the stored hashes of watched settings no longer match their values. The config watch notices the change, alerts the administrators once and records the watched settings again; [Keys and fingerprints](keys.md#changing-the-instance-secret) describes what the change resets and what to do about it.

## Algorithms and migration

The app uses only symmetric primitives: HMAC-SHA256 and core's `ICrypto`. Stored fingerprints carry no algorithm or key version; moving to another algorithm would mean the same as rotating the `secret`: values made before are no longer recognised, and the app makes new ones as it goes. No asymmetric cryptography is used, so the move to post-quantum algorithms does not concern the app.
