<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Functionality that needs care

The parts of the app that start processes, run admin-supplied patterns,
parse data from other servers or write outside Nextcloud, and what keeps
each of them in bounds. The app has no `eval`, `unserialize`, `exec`,
`shell_exec`, `system` or dynamic `include`.

| What | Where | Protections |
| --- | --- | --- |
| Starting a PHP process | `occ intrusion:benchmark` (`Perf\FreshRequestProbe`) | Runs only from occ, never from a web request. Starts `php -r` with a fixed code string and an argument list, without a shell. |
| Admin-supplied regular expressions | custom signatures of the injection check (`Check\Checks\InjectionProbe\CustomSignatures`) | Admin only, at most 50 of 300 characters. A control character delimits the pattern, so no flags can be injected. Checked when saved for compiling, matching an empty value and speed; a backtracking limit applies on every request. See [Resource limits](limits.md#custom-signatures). |
| Patterns on every request | the request guards and the injection check | A pre-filter finds most requests clean in one pass. The built-in signatures use bounded quantifiers, and the input is capped per field and per request. |
| Data from other servers | blocklists (`Blocklist\`), the breached-password check (`Breach\PwnedPasswordsClient`) | Off until an admin switches them on. `https://` only, local and private addresses refused, every redirect checked again, size and entry limits, JSON decoded into arrays only. A list that fails to parse keeps the previous version in use. |
| Web server configuration | the nginx and Apache snippets for trap paths (`Traps\TrapPathSnippets`) | Generated text that an admin copies by hand; the app never writes web server configuration. Only paths made of letters, digits and `/._~-` go into a snippet; others are listed as left out. |
| Files outside the data directory | the firewall export (`Export\`) | The directory can only be set in `config.php`. It must not be inside the data directory or the Nextcloud installation, nor contain it, and must not be world-writable. Files are written with mode 0640 to a temporary file and renamed into place. |
| Multi-row SQL | `Db\MultiRowInsert` | Built from fixed table and column names; every value is a bound parameter. |
| Private core classes | listed in [ARCHITECTURE.md](../ARCHITECTURE.md#private-core-classes) | Can change in any Nextcloud release, so `info.xml` allows one server version only. |
