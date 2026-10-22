<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Architecture

The namespaces of `lib/` form layers. A namespace may use its own layer and
the layers below it, never one above. `tests/Unit/ArchitectureTest.php`
enforces this on every test run.

| Layer | Namespaces | Owns |
| --- | --- | --- |
| adapters | `AppInfo`, `Listener`, `Guard`, `Middleware`, `Dav`, `Controller`, `Command`, `BackgroundJob`, `Settings`, `SetupCheck`, `Dashboard`, `Repair`, `Migration`, `Perf` | Turning core's events, requests, routes, jobs and occ calls into calls of the layers below. Thin. |
| pages | `Admin`, `Personal` | What the admin and personal pages show, built from the features. |
| features | `Check\Checks`, `Check\CredentialUse`, `Check\Payload`, `Address`, `AdminChange`, `Blocklist`, `Breach`, `Confirm`, `Decoy`, `Export`, `Guide`, `Incident`, `KnownDevice`, `Learning`, `LoginHistory`, `OpenMetrics`, `Privacy`, `Risk`, `SessionState`, `Share`, `StaleCredential`, `Takeover`, `Traps`, `TrustedNetwork`, `WasThisYou` | One check or one feature each: its definition, detection, texts and state. |
| platform | `Check`, `Detection`, `Response`, `Explain`, `Event`, `Notification`, `Login` | The check registry and capability interfaces, recording detections, running responses, explanation texts, events and notifications. |
| storage | `Db`, `Config` | Tables and mappers; settings, the config lexicon and its keys. |
| kernel | `Definition`, `Net`, `Crypto`, `Audit`, `Http`, `ResponseDefinitions`, `Sensitive`, `Cache` | The shared vocabulary and the memory caches. Uses nothing above it. |

## Rules

- **`Definition` uses nothing else of the app.** It holds what a check is
  made of: `CheckDefinition` with its texts, `Mode`, `Severity`,
  `ResponseType`, the parameter types, `Requirement`, `ProtectionLevel` and
  `InvalidParamException`.
- **Generic code names no check.** Per-check rules are properties of the
  check's `CheckDefinition` (for example `honoursLure`,
  `trustedLoginsExempt`, `confirmedLoginsExempt`, `userAlertInterval`,
  `digestSection`), and the platform reads them through `CheckRegistry`.
  Only a check's own feature code names it.
- **`Net` is a leaf of plain address values.** Anything that needs the
  database lives above it, as `Db\KeyMatch::slash64sIn()` or
  `Response\ProxySuspect` do.
- **Per-user config keys** are declared once, in `Config\UserKeys`.
- **Memory caches come from `Cache\Caches`**, one namespace per consumer,
  declared by the consumer (its `CACHE` constant). `shared()` is the
  distributed cache when one is configured, else the local one;
  `isDistributed()` is the one answer to whether the cache is shared by all
  web servers.
- **The plain request path stays cheap.** Registries are lazy class-string
  lists (`CheckRegistry::CHECKS`, `ResponseEngine::HANDLERS`,
  `Application::SETUP_CHECKS`). Registering the app reads no constant of
  another class, so the listener priorities live in `Application`.

## The allow-lists

`ArchitectureTest` lists today's exceptions, each with its reason:

- `ALLOWED_UPWARD`: dependencies that still point upward.
- `NAMES_A_CHECK`: generic files that still name a check.

These lists may only shrink. A change that removes an exception removes its
entry; the test fails while a fixed entry is still listed. A new namespace
must be added to a layer here and in the test.
