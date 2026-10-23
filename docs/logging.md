<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Logging

Where the app writes what it sees and does, what each place holds, and how long it is kept.

## Where it writes

| Place | What | Personal data | Kept |
| --- | --- | --- | --- |
| Detections (database, the admin page) | Every detection: the check, the address, the account, the measured values, what was done | Addresses and accounts in clear; request excerpts of injection probes | `retention_detections_days`, 90 days by default |
| Audit log (`admin_audit`, through core's `CriticalActionPerformedEvent`) | Every new detection, and the actions listed below | Addresses and accounts in clear | As long as you keep the audit log |
| `nextcloud.log` | Errors and warnings of the app itself | The account where a message names it (`{uid}`); core adds the request's address, account and URL to every entry | As long as you keep `nextcloud.log` |
| `bans.log` in the firewall export folder | One line per block and per lift, for fail2ban | Addresses | Rotated to `bans.log.1` at 10 MB; one old generation is kept |
| Webhooks (the Webhooks app) | `DetectionCreatedEvent`, `BanCreatedEvent`, `BanLiftedEvent` | Accounts; addresses only when "Addresses in webhook events" is on | By the receiving system |
| Notifications and emails | Alerts to administrators, users and share owners | Addresses and accounts in the text | By the notifications app and the mailboxes |
| OpenMetrics | Counts by check, severity and list | None | By the metrics system |

Passwords, codes, tokens, decoy secrets, session ids and device ids are never written to any of these. Parameters that carry them, and login names (often a password typed into the name field), are marked `#[\SensitiveParameter]`, so a logged stack trace shows a placeholder instead. A test fails when such a parameter is not marked.

## The audit log

Every line names who acted (an account, `occ`, or the app itself) and what it acted on. The messages, grouped:

- **Detections:** `<check> detected (<severity>, <mode>), source <address>, account <account>`.
- **Logins:** a login needs extra confirmation, was confirmed, allowed without confirmation, refused, given up, or ended because nobody confirmed it; a session whose login was never confirmed came back and was ended.
- **Responses to an account:** sessions and app passwords ended, a token revoked, a new password required or no longer required, a password to be reset in an external directory, known devices forgotten, an account locked with a lock link or enabled again, an open lock link ended by "Yes, it was me".
- **The user's answers:** "Yes, it was me" and "No, it was not me", networks trusted and removed, devices removed, "Log out everywhere else", unused app passwords and devices removed.
- **Blocks and lists:** blocks added and lifted (with the reason given), lists changed, downloaded and removed, share links disabled from a notification.
- **Approvals:** requested, approved, rejected, expired, withdrawn, or not stored.
- **Settings:** checks changed or reset, settings changed or reset, the protection level, learning mode started, extended or ended, intrusion detection turned on or off, trap paths, reserved names and decoys changed.
- **Reports and tests:** incident reports generated, test alerts and test digests sent.

## `nextcloud.log`

- **Error:** a step of the app failed (recording a detection, a response, a listener, a background job, a setup check). The request or job goes on; the exception is logged with its trace.
- **Warning:** an outside service or limit got in the way: the Pwned Passwords service or a blocklist could not be reached, the firewall export could not be written, the hourly cap of user emails was reached, the data of a deleted account could not be removed yet.
- **Info:** a downloaded list was not taken, with the reason.
- **Debug:** the result of a digest, and a session whose token id could not be read.

## Web server access logs and lock links

After an email change in an account takeover, the previous address gets a link that locks the account: `/apps/intrusion_detection/lock/<id>/<token>`. The token is in the path, so web server and proxy access logs record it, and so does the URL of any `nextcloud.log` entry written while the page is shown.

What someone with the token can do is limited: opening the link changes nothing, locking needs a second step from the page, the link works once, ends after 7 days or as soon as the account holder answers "Yes, it was me", and it can only lock the account, never unlock it or change anything else.

Keep access logs no longer than you need them, and restrict who can read them, as for any log with addresses. Block references (`ABCD-EFGH`) shown to blocked visitors are lookup labels, not secrets.
