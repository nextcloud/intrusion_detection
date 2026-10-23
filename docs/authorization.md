<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Who may do what

The access rules of the app, and how it keeps the administrators it
watches from switching it off unnoticed.

## Administrators

Every admin page and admin API endpoint is for full administrators only:
members of the `admin` group, through Nextcloud's own admin check, which
also applies the admin IP allowlist of `config.php`. No part of the app
can be delegated, and group administrators (sub-admins) have no access to
it. The `occ intrusion:*` commands are for whoever runs `occ` on the
server.

Changes of settings, blocks, decoys and accounts need a recent password
confirmation, and every change is written to the audit log. Rejecting a
request for approval needs no password, so that stopping one is quick.

## Users

The personal security page and its API show only the logged-in user's
own data: their detections, logins, trusted networks, remembered
browsers, security changes and unused app passwords. The account is
always taken from the session, never from the request, and an id of
someone else's entry answers "not found".

What a user sees of a detection is written for them: what happened, when
and from where, what Nextcloud did and what to do. Never the limits of a
check, other accounts or the administrators' notes.

"Yes, it was me" needs a password confirmation and a login confirmed by
more than the password (a second factor, an email code, an
administrator's approval or a remembered browser), from another session
than the one the question is about. "No, it was not me" from a session
that only knew the password is recorded and told to the administrators,
but does not act.

The pages of a login that waits for its confirmation (`/verify`,
`/notice`, `/password`) act only on the current session's own login.

## Without an account

Only two pages need no login:

- the **lock link** (`/lock/{id}/{token}`), sent to the previous email
  address after an account takeover sequence. Opening it changes nothing;
  locking needs the page's own one-time value, works once and expires
  after 7 days. It can only lock, never unlock. The last enabled
  administrator is not disabled by it, only logged out everywhere, since
  only the command line could enable it again.
- `/verify/ended`, which says that a login was ended.

## Approvals

A request for approval is decided by another enabled member of the
`admin` group:

- the account a request is about can never decide it;
- the administrator who asked can only withdraw it (reject it);
- delegated and group administrators can never decide;
- approving needs a password confirmation, and the approving
  administrator's own login must have been confirmed;
- only one decision wins, and a request expires after its time (7 days
  for administrators and settings changes);
- `occ intrusion:approvals:decide --approve --as=<uid>` follows the same
  rules for the administrator named with `--as`.

## Four-eyes approval

With "A second administrator approves new administrators" switched on,
one administrator alone cannot give administration rights or end the
approval:

- An account added to the `admin` group, or to a group with delegated
  administration settings, from the web interface or the API is taken out
  again at once and becomes a request. Approving adds it.
- A change from the admin page or the API that would end the approval is
  held back the same way, as a request of the kind "settings": switching
  the approval off, switching intrusion detection off, setting the admin
  change alerts below Protect, or "Reset all settings". Approving makes
  the change as it was asked.
- An error of the approval check takes an addition back and asks for
  approval, rather than letting it stand.

Not held back, and reported as a high detection all the same:

- `occ`, and background jobs on the command line: whoever can run them
  controls the server already;
- memberships a user directory such as LDAP holds: Nextcloud cannot undo
  them;
- changes made around the app, such as `occ config:app:set` or the
  provisioning API.

## Tamper resistance

The admin change alerts watch the administrators, so they are built not
to go quiet when someone with administrator rights turns against them:

- **The config watch never goes silent.** Switching the admin change
  alerts or intrusion detection off, also around the app, is itself
  reported. While they are off, the watch keeps the last state it saw;
  when they are back on, everything that changed in between is reported.
- **Switching the app off is told at once.** The email goes out right away
  instead of through a background job, and the bell notification goes
  through the admin notifications of Nextcloud's notifications app, so
  both reach the administrators although the app stops.
- **A shorter retention waits seven days.** Lowering "Keep records for"
  deletes nothing older until seven days later, so the record of what
  happened outlives the alert about the change.
- **The protective settings can be locked.** With
  `'intrusion_detection.locked' => true` in `config.php`, intrusion
  detection stays on, the admin change alerts stay in Protect, and the
  four-eyes approval stays on, whatever is stored. Neither the admin page,
  the API, "Reset all settings" nor `occ` can change them; only removing
  the line from `config.php` does. New administrators then always need a
  second administrator's approval, or `occ`. The lock shows in
  `occ intrusion:status` and on the admin page.

Switching the app off in Nextcloud's app management cannot be prevented
by the app; it is reported as described above.
