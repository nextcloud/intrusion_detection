<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Keys and fingerprints

What the app keeps instead of secrets, which key protects it, and what
changing the instance `secret` does.

## One root key

The app has no key of its own. Every key it uses is derived from the
instance `secret` in `config.php`, which Nextcloud creates at
installation and which never leaves `config.php`:

    key(purpose) = HMAC-SHA256(secret, "intrusion_detection/" + purpose)

Each purpose gets its own 256-bit key, so a fingerprint made for one
purpose cannot be compared with one made for another. All of this lives
in one class, `Crypto\Fingerprinter`. Without a `secret`, it refuses to
work instead of hashing without a key.

## What is kept as a fingerprint

| Purpose | Input | Kept as | Where, and for how long |
| --- | --- | --- | --- |
| `name` | login names and reset inputs of failed attempts | HMAC-SHA256, 128 bits | failed attempts, 1 hour |
| `share_token` | share tokens of failed share accesses | HMAC-SHA256, 128 bits | failed attempts, 1 hour |
| `password/<day>` | passwords of failed logins | HMAC-SHA256, 128 bits, key changes every day (UTC) | failed attempts, 1 hour; flags, at most 1 day |
| `credential/<day>` | presented app passwords and session tokens | HMAC-SHA256, 96 bits, key changes every day | memory cache only |
| `decoy` | decoy secrets | HMAC-SHA256 | until the decoy is deleted |
| `device` | remembered-browser ids | HMAC-SHA256 | until the browser is forgotten (180 days unused) |
| `session` | PHP session ids of logins that wait for their confirmation | HMAC-SHA256, 128 bits | until the login is confirmed or ends |
| `lock_link` | lock link tokens | HMAC-SHA256 | 7 days, one use |
| `setting` | the values of the watched settings | HMAC-SHA256 | the config watch snapshot |

Secrets are compared in constant time (`hash_equals`), or looked up by
their fingerprint.

## What is encrypted

Two values are encrypted with Nextcloud's `ICrypto` (AES-256-CBC with
HMAC-SHA512, encrypt-then-MAC), which is also keyed with the instance
`secret`:

- the previous email address after an email change, for one day, so that
  the lock link can be sent there;
- cached answers of the breached-password check, for one day.

Email confirmation codes are hashed with Nextcloud's password hasher and
are valid for 10 minutes.

## Changing the instance secret

Nextcloud does not rotate `secret` by itself, and the app has no
schedule for it. An administrator who changes it should know what it
resets in this app, because every stored fingerprint was made with the
old key and nothing tells the keys apart:

- **Decoys.** A decoy's secret no longer matches. A decoy with a login
  name is still noticed by that name, as the weaker sign. Delete the old
  decoys and create new ones. A setup check lists the decoys created
  before the change.
- **Remembered browsers** are forgotten: their next login is treated as a
  new device.
- **Lock links** that were sent and not used stop working.
- **Logins that wait for their confirmation** are remembered on the server
  by a fingerprint of their session id. After the change, such a login
  that comes back with its remember-me cookie, without its session data,
  is no longer recognised as unconfirmed. A remembered login lasts 15
  days unless `remember_login_cookie_lifetime` says otherwise.
- **The config watch** finds that the secret changed (it keeps a
  fingerprint of a fixed text under the current key). It records one high
  detection about the change, which tells the administrators the above,
  and records every watched setting again without reporting each of them.
  Changes of other settings made in the same five minutes are recorded as
  the new state, not reported.
- Failed attempts and flags made with the old key are no longer linked to
  new ones; they expire within a day anyway.

## Algorithms and the future

The app uses only symmetric primitives: HMAC-SHA256 and Nextcloud's
`ICrypto`. SHA-1 is used only because the Have I Been Pwned range API
requires it, and only for the 5-character prefix that is sent. To move
to another algorithm, `Fingerprinter` is the one place to change; the
stored fingerprints would then be replaced the way a change of `secret`
replaces them.
