<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Logins and their confirmation

This page says which logins Intrusion detection holds to a confirmation, how
long each step may take, and what the lock link puts into access logs.

## Which logins are confirmed

A login needs confirmation when one of the reasons applies: the address took
part in an attack, the password is being sprayed or is on a breach list, the
account is under attack, the address is a hosting or Tor network or has a
high risk score, or an administrator logs in from outside the trusted
networks while "Administrators log in with their password from trusted
networks only" is on.

| How the login happens | What the app does |
| --- | --- |
| Login form with the password | All reasons. Confirmed with the second factor, a remembered device, an emailed code or an administrator's approval, in this order. |
| Another login that hands core the password (for example an SSO backend with a stored secret) | Treated like the login form. |
| An app or script that sends the account's password (Basic auth) | All reasons, but it can never answer a confirmation: it is refused and pointed to app passwords, or let in where the reason's setting allows it. Lenient reasons let it in from a familiar place. |
| App passwords (Basic auth) and OAuth2 Bearer tokens | No reasons. A session that comes back with a token after its login was never confirmed is ended. |
| Single sign-on without a password (`user_oidc`, `user_saml`, `apache_backend` without a secret) and passwordless logins (WebAuthn) | No reasons, including the administrator network rule. The identity provider's own policies apply. |
| A browser that comes back with its remember-me cookie, or a session core restores from its token | No new reasons. A login that was never confirmed cannot come back this way: its session is ended. An administrator's session is held to the network rule (below). |
| Any login from an address on the brute-force allowlist | Only the administrator network rule; every other reason is skipped. |

A login that waits for its confirmation, or was refused, reaches nothing but
the verify page, logging out and core's second-factor pages. This holds on
every `remote.php` endpoint, including the old `remote.php/caldav`,
`/calendar`, `/carddav` and `/contacts` addresses.

Once a login is confirmed, its session continues under a new session id, on
servers whose core can renew the id and keep the session's token
(`OCP\Session\ISessionIdRenewer`). The token keeps its id, so the login
history and detections stay linked to the session. Other servers keep the
session id.

### Administrators

While "Administrators log in with their password from trusted networks only"
is on:

- an administrator's password login from outside the trusted networks must
  be confirmed; a remembered device is not enough;
- an administrator's browser session that was let in without such a
  confirmation ends when it is used from outside the trusted networks. The
  networks are read on every request, so removing a network ends the
  sessions it let in;
- an account that becomes an administrator loses its browser sessions and
  logs in again;
- when the rule cannot be evaluated (for example the group backend fails),
  it applies. When deciding the login fails while the rule applies, the
  login is ended.

Administrators confirm with the second factor or another administrator's
approval. An emailed code is offered to an administrator only when neither
is available.

Approving a new administrator or a held settings change needs a login
that proved more than the password: a second factor, an emailed code, an approval or a remembered
device. A client that sends the password with Basic auth cannot approve.

## Labels on the personal page

Each login on the user's Account protection page gets plain labels, worked
out when the page is shown from data the app keeps anyway. A login is
compared with the account's logins of the 30 days before it that went
through (needed nothing, or were confirmed); refused, failed and waiting
logins never count.

| Label | When |
| --- | --- |
| Your usual network | The network (/24 for IPv4, /64 for IPv6) is one the user trusts after "Yes, it was me", or one of those logins came from it |
| New network | Neither, while there were such logins |
| New device | Not a remembered device, and none of those logins came from the same browser on the same system ("Firefox on Windows"); never for a client that names neither |
| Unusual hour | A login in the browser (password, single sign-on or a remembered login) more than an hour away, in the user's time zone, from each of at least 5 such logins before it. App logins have no hour |

Nothing new is claimed where the history cannot tell: before the first login
that went through, and where the 30 days before a login reach back past the
retention of the login history (the retention of detections) or past the
500 logins before the shown ones the page reads. There only "Your usual
network" is said. The address stays in the row as before; the labels show
nothing the page did not show.

## "Was this you?" next to the habit

An open "Was this you?" question on the Account protection page, and on
the security notice for users Nextcloud cannot reach by email, is put next
to the account's habit in two lines:

- what the event was: the device its user agent names ("Firefox on
  Windows"), "new network" or "your usual network" as in the labels above,
  and the time in the user's time zone, with "an unusual hour for you" by
  the same rule as the label;
- how the user usually logs in: the browser and system most of the
  account's logins in the browser of the 30 days before came from, when at
  least 3 did ("You usually log in with Chrome on macOS"), followed by
  "from your usual network" when the event's network is new.

Logins in the 5 minutes before the event are left out: they may be the
event's own login. The same limits as for the labels apply: nothing new is
claimed where the login history does not reach back 30 days. The security
notice shows the comparison only where the Account protection page, which
lists the logins, is shown. Nothing is stored for it.

## Timers

| What | How long |
| --- | --- |
| A login waits for its confirmation | 15 minutes, then it is ended (on its next request, or by the background job) |
| An emailed code is valid | 10 minutes |
| An administrator is asked to approve a login | 10 minutes; the login may wait until then if that is later than its own 15 minutes |
| A refused login keeps its session to show why | 5 minutes, or until the user leaves the page |
| An app refused at its login | Its session ends at its first refused request |
| The decision about an app that sends the password is repeated without the checks | 60 seconds |
| A remembered device | 180 days after its last use |
| A network trusted with "Yes, it was me" | 30 days |
| The record of a session whose login was never confirmed | As long as core could resume it: the longer of `remember_login_cookie_lifetime` (15 days by default) and `session_lifetime` (1 day), plus an hour |
| A lock link | 7 days, once |

## Limits

| What | Limit |
| --- | --- |
| Tries of an emailed code | 5 per login |
| Codes sent to an account | 5 per hour |
| Wrong codes for an account, across its logins | 10 per hour; then no code is sent or checked for the account until the hour has passed |
| New codes for one login | 3 per 10 minutes |
| New password on the password page | 8 characters where no password policy app decides; not on the breach list while the breach check runs |

## Lock links and access logs

After an email address changed in a sequence that looks like a takeover,
the old address gets a link to lock the account. The token is part of the
link's path (`/apps/intrusion_detection/lock/<id>/<token>`), so web servers
and proxies write it into their access logs when the link is opened.

The token can do one thing only: lock that account, once, within 7 days.
Opening the link shows a page; locking needs a click on it, which sends the
page's form with a one-time value bound to the session. The page tells the
browser not to cache it and not to send it as a referrer.

If your access logs are read by more people than your administrators, mask
the path `/apps/intrusion_detection/lock/` in them, or keep them as
protected as the server itself.
