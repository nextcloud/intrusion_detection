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
| features | `Check\Checks`, `Address`, `AdminChange`, `Blocklist`, `Breach`, `Confirm`, `Decoy`, `Export`, `Guide`, `Incident`, `KnownDevice`, `Learning`, `LoginHistory`, `OpenMetrics`, `Privacy`, `Risk`, `SessionState`, `Share`, `StaleCredential`, `Takeover`, `Traps`, `TrustedNetwork`, `WasThisYou` | One check or one feature each: its definition, detection, texts and state. |
| platform | `Check`, `Configure`, `Detection`, `Response`, `Signal`, `Explain`, `Event`, `Notification`, `Login` | The check registry and capability interfaces, validated settings writes, signals and their dispatch to the detectors, recording detections, running responses, explanation texts, events and notifications. |
| storage | `Db`, `Config` | The shared records and their helpers; reading the settings, the config lexicon and its keys. |
| kernel | `Definition`, `Net`, `Crypto`, `Audit`, `Http`, `ResponseDefinitions`, `Sensitive`, `Cache`, `State` | The shared vocabulary, the memory caches and the app's internal state. Uses nothing above it. |

## Rules

- **One folder per check.** `Check/Checks/<Name>/` holds the check's
  definition and texts (`<Name>`), its detector (`<Name>Detector`, listed
  in `CheckRegistry::DETECTORS`), its facts (`<Name>Facts`, with a
  `<Name>Rule` enum where it has rules) and the classes only that check uses, such as the payload matching of
  `InjectionProbe` or the credential tracking of `TokenConcurrentUse`.
- **Facts are typed.** A check's facts class is what its detections
  record: the detector and the simulation build it, the check's texts
  read it back with `fromArray()`, and it declares how a repeated hit
  merges (`Detection\IMergeableFacts`). The facts that many checks record
  and generic code reads (first, last, targets, the risk score, the
  linked sessions, simulated) are one `Detection\CommonFacts`. A key a
  detection did not record stays out of the stored JSON, so rows keep
  their shape; `tests/Integration/StoredDetectionsTest.php` pins how
  stored rows read and merge.
- **A table belongs to its feature.** A feature's mappers and entities live
  in its `Db/` sub-namespace (`KnownDevice\Db\KnownDeviceMapper`), which is
  part of the feature. Other features use that data through the feature's
  service, not its mapper. Only records several layers share stay in `Db`:
  detections, blocks, attempts, approvals, logins and app password origins,
  with the helpers `KeyMatch`, `BatchedDelete` and `MultiRowInsert`. The
  daily failed-login counts stay too: their owner is the personal page,
  above the privacy cleanup that deletes them.
- **Each owner keeps its own retention.** The owner of a table implements
  `Db\IPurges` with its retention constant or setting; the cleanup job only
  runs the owners listed in `Cleanup::PURGES`, in order, each in its own
  try/catch. `tests/Integration/TableOwnersTest.php` reads the app's tables
  from the database schema and fails for a table without a purge owner and
  an entry in `Privacy\UserDataCleanup`, unless it lists the reason.
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
- **Reading settings builds no definition.** `Config\CheckSettings` (modes,
  parameters, responses) and `Config\AppSettings` (typed getters of the
  global settings) read with the static `LexiconData` only. Writes go
  through `Configure\SettingsEditor`, the one place that validates against
  `CheckRegistry` and dispatches `SettingChangedEvent`. A global setting that
  belongs to a check is listed in that check's `CheckDefinition::$globals`.
- **Memory caches come from `Cache\Caches`**, one namespace per consumer,
  declared by the consumer (its `CACHE` constant). `shared()` is the
  distributed cache when one is configured, else the local one;
  `isDistributed()` is the one answer to whether the cache is shared by all
  web servers.
- **Internal state is no setting.** What the app records for itself lives in
  `State\AppState` (the `ids_state` table), each name declared by the class
  that owns it (for example `DigestSender::STATE`). Only the few small values
  that requests read often stay in the app config, in `State\HotState`. The
  app config holds the settings an administrator chooses.
- **The plain request path stays cheap.** Registries are lazy class-string
  lists (`CheckRegistry::CHECKS`, `CheckRegistry::DETECTORS`,
  `ResponseEngine::HANDLERS`, `Application::SETUP_CHECKS`). Registering the app reads no constant of
  another class, so the listener priorities live in `Application`.

## How a detection flows

1. **An adapter makes a signal.** A listener, guard or service turns what
   happened into a small value object in `Signal\` (`FailedLogin`,
   `FailedLoginAttempt`, `SuccessfulLogin`, `ShareAccessFailed`,
   `ResetRequested`, `AdminChanged`, …), or a check's own signal in its
   folder (`TokenConcurrentUse\CredentialSwitched`). Secrets in a signal are
   `#[\SensitiveParameter]` and left out of `__debugInfo()`.
2. **The dispatcher picks the detectors.** `Signal\SignalDispatcher` reads
   the detectors of the signal from `CheckRegistry::DETECTORS`, in order,
   keyed by check id. A detector whose check does not run is neither loaded
   nor built; each one that runs gets the mode and its own try/catch. A
   listener asks `runs()` or `acts()` before work it does only for the
   checks, such as recording an attempt.
3. **A detector returns drafts.** It implements `IDetector`, reads data and
   returns `DetectionDraft`s; it never records, answers or reads its mode.
   A final draft (a decoy, a reserved name) ends the chain. A detector that
   needs the stored detection is a generator and gets it back from `yield`.
4. **The engine records and answers.** `ResponseEngine::handle()` takes
   the mode from the check, or from the draft for the few that run in
   another one, stores the detection and runs the responses the check
   selects for it (`ISelectsResponses`). Nobody else passes responses.
   A hit that joins a stored detection merges its facts by the rules of
   the check's facts class (`Detection\FactsMerger`).

Code whose finding is itself the detection (a guard's trap or payload
hit, a counter over its limit, a step-up outcome, the account holder's
"No", a lock link) builds its draft and hands it to the engine directly.

## The allow-lists

`ArchitectureTest` lists today's exceptions, each with its reason:

- `ALLOWED_UPWARD`: dependencies that still point upward.
- `NAMES_A_CHECK`: generic files that still name a check.

These lists may only shrink. A change that removes an exception removes its
entry; the test fails while a fixed entry is still listed. A new namespace
must be added to a layer here and in the test.
