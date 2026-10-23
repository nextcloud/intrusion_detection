<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Resource limits

The limits that bound what the app costs, and what happens when one is
reached. They are fixed in the code, not settings.

## Outgoing connections

The app connects out only for blocklists and the breached-password check,
and only when an admin switches them on.

| | Blocklists | Breached-password check |
| --- | --- | --- |
| Address | `https://` only, no user name or password in it, no local or private address | `https://api.pwnedpasswords.com/range/` |
| Timeouts | 10 s to connect, 60 s in total | 1 s to connect, 1.5 s in total, because a login waits for it |
| Redirects | at most 3, each `https://` and checked like the address itself | none |
| Size | the download stops after 10 MB | an answer over 512 KB is refused |
| How often | every 6 hours, or the list's own interval, at least 15 minutes apart | at an interactive login when the password changed or the last check is older than the recheck period; answers are cached for a day |
| On failure | the list in use stays in use; the failure shows on the admin page and as a setup check | the login goes on; the password is checked again at the next interactive login |

A blocklist is also refused when it is empty, has more than 200,000
entries or more than 1 % malformed entries. At most 50 lists can be set up.

## Work per request

A plain request costs a few memory-cache lookups; see "Light on
resources" in the README. The injection check looks at a request only
within fixed bounds:

- at most 1,000 query parameters and form fields, and at most 64 KB of the
  path, the query and each form field;
- the request body only as far as PHP has already parsed it into form
  fields; JSON and other bodies are not read;
- percent-encoding is undone at most twice, base64 at most two levels deep
  and only for values of 16 to 8,192 characters.

### Custom signatures

Admins can add up to 50 regular expressions of at most 300 characters each.
They run on every inspected value, so they are checked when saved:

- they must compile and must not match an empty value;
- they run with a backtracking limit of 100,000 steps, when saved and on
  every request;
- when saved, each one runs against long adversarial input (16 KB per
  sample) and is refused if all samples together take more than 50 ms.

A signature that passes these checks still runs on every value the check
inspects. Try new ones with `occ intrusion:payload:test` and watch the cost
with `occ intrusion:benchmark`.

## Stored data

- **Failed attempts** are kept for one hour. When more than 100,000 are
  stored, the app counts as flooded for 10 minutes: unknown share tokens
  and password reset requests are then sampled, one in 10 is stored with
  a weight of 10. Failed logins are always stored. The flood state is set
  by the cleanup job, which runs every 5 minutes with background jobs; with
  AJAX background jobs it can lag.
- **Incident reports** cover at most 90 days and hold at most 2,000
  entries. A longer report is marked as truncated.
- **Detections and blocks** come at most 100 per page from the admin API.

## Rate limits

Every request of a user or of a public page that changes something or
sends an email (confirming, denying, removing a device, sending a code,
locking an account) has a limit in core's rate limiter; above it the answer
is HTTP 429. Pages and endpoints that only read have no limit of their
own, and neither do most admin endpoints.
