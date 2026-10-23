<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Browser security

What the app's pages expect from the browser and from the server setup.

## Use HTTPS

"Remember this device" stores a random device id in a cookie. A later
login from that browser skips the login confirmation, so the cookie is as
valuable as a second factor.

- The cookie is `HttpOnly` and `SameSite=Lax`, valid for the Nextcloud web
  root, and is kept for 180 days after the device was last used.
- It is marked `Secure` when Nextcloud sees the request as HTTPS. Behind a
  reverse proxy, set `overwriteprotocol` and `trusted_proxies` so that it
  does.
- Over plain HTTP the cookie travels unencrypted, and anyone who can read
  the traffic can copy it. Serve Nextcloud over HTTPS only, ideally with
  HSTS.
- Only a keyed fingerprint of the device id is stored on the server.
  Rotating the instance `secret` makes every remembered device unknown.

## Content Security Policy and framing

The app does not relax the server's defaults:

- Every page keeps Nextcloud's Content Security Policy with its script
  nonce. No template has inline scripts, and nothing in the app uses
  `eval` or HTML from translations or user input.
- No page relaxes `frame-ancestors`, so the pages can only be framed by
  Nextcloud itself. The lock page also needs a value from the same page to
  lock the account.
- The incident report download is an attachment with `nosniff` and its own
  policy (`default-src 'none'`): it can run no script, load nothing and
  submit no form. The admin page prints it in a sandboxed frame.
- The lock page sends `Referrer-Policy: no-referrer`, `Cache-Control:
  no-store` and `X-Robots-Tag: noindex`, because its address carries a
  token.

## Pages that work without JavaScript

The pages a user can meet during a login are plain HTML forms:

- confirming a login (email code, second factor, asking an administrator);
- waiting for an administrator's approval: the page checks by itself with
  JavaScript, and has a "Check now" button without it;
- "Was this you?" notices, the lock page and the forced password change.

The admin settings, the personal security settings and "Secure my
account" are Vue apps and need JavaScript.

## Links and redirects

- After a confirmation, the app only continues to a path on the same
  Nextcloud. Other targets are ignored.
- External links (documentation, Have I Been Pwned, blocklist terms) are
  fixed addresses and open with `rel="noreferrer noopener"`.
