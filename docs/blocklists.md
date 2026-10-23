<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Blocklists and the firewall export

## What you trust when you switch a list on

A list decides which addresses are refused (blocklists) or treated as hosting or Tor networks. Its integrity rests on two things:

- **https.** Lists are downloaded only from `https://` addresses, with the certificate checked against Nextcloud's CA bundle.
- **The publisher.** Whoever can change the file at its source changes what your server blocks. The built-in lists come from Spamhaus, FireHOL (through `raw.githubusercontent.com`, so a change of that GitHub repository reaches you), Amazon Web Services, Google Cloud, Oracle Cloud, DigitalOcean and the Tor Project. All of them are off until you switch them on.

What a bad list can do is limited: the worst case is that addresses are blocked that should not be. The app never blocks loopback, the server's own addresses or addresses on the brute-force allowlist, and it leaves out ranges that touch private or reserved address space. A list set to Observe only counts matches.

**Pin a list that rarely changes.** For your own lists you can give the SHA-256 the file must have, in the add dialog, in the list's details, or with `occ intrusion:blocklists:set <list> --sha256 <checksum>`. A file with another checksum is not used: the list keeps the version it had, and the admin page says why. A pinned list is downloaded in full every time, and you update the checksum when the list changes. Built-in lists change often and cannot be pinned.

## Your own lists

Formats a list may have:

- **Plain text:** one address or range per line (`192.0.2.0/24`, `2001:db8::/48`, or a single address); `#` and `;` start a comment.
- **Spamhaus DROP:** JSON lines with a `cidr` field.
- **Amazon Web Services** `ip-ranges.json`, **Google Cloud** `cloud.json`, **Oracle Cloud** `public_ip_ranges.json`.
- **Geofeed CSV** (RFC 8805), as DigitalOcean publishes it.

Limits for every list:

- at most 10 MB, counted after decompression; a larger download is stopped;
- at most 200,000 entries; parsing stops at the first one over;
- at most 1 % entries that are not address ranges;
- at least one range;
- at most 50 lists, the built-in ones included, downloaded every 6 hours by default (15 minutes to 7 days per list);
- at most 3 redirects, each to an `https://` address checked like the list's own; 10 seconds to connect, 60 seconds in all.

A list that fails any of these keeps the version it had.

## Addresses the server may download from

The address of a list is checked when you save it, before every download and at every redirect: `https://` only, no user name or password in it, and a host that core's remote host check accepts, so not in the local network. Core also pins the resolved address of the host for the connection (DNS pinning), so a host name cannot point somewhere else between the check and the download.

Two core settings in `config.php` weaken this, and the app cannot tell:

- `allow_local_remote_servers => true` lets lists, like every other outgoing request of Nextcloud, point into the local network.
- `dns_pinning => false` leaves only the check of the host name, which a host whose DNS answer changes can get around.

## The firewall export folder

The export (`intrusion_detection.export_dir` in `config.php`) writes the active blocks and `bans.log` to a folder that your firewall reads. The app refuses a folder inside the data directory, inside the Nextcloud installation or an apps folder, a folder that contains the installation, and a world-writable one. It cannot know which other folders your web server serves: choose a folder outside every web root, for example `/var/lib/nextcloud-ids`, so that the list of blocked addresses is never public.
