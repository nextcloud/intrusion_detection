<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection;

/**
 * @psalm-type IntrusionDetectionParam = array{
 *     name: string,
 *     type: string,
 *     default: int|float|bool|string|list<string>,
 *     min: int|float|null,
 *     max: int|float|null,
 *     choices: list<string>,
 *     value: int|float|bool|string|list<string>,
 *     label: string,
 *     help: string,
 *     unit: string,
 * }
 *
 * @psalm-type IntrusionDetectionCheckResponse = array{
 *     type: string,
 *     label: string,
 *     happens: string,
 *     order: int,
 *     selected: bool,
 *     default: bool,
 * }
 *
 * @psalm-type IntrusionDetectionRequirement = array{
 *     id: string,
 *     met: bool,
 *     text: string,
 * }
 *
 * @psalm-type IntrusionDetectionModeState = array{
 *     configured: string,
 *     effective: string,
 *     reason: ?string,
 *     missing: ?string,
 *     default: string,
 * }
 *
 * @psalm-type IntrusionDetectionCheckTexts = array{
 *     name: string,
 *     summary: string,
 *     detects: string,
 *     decides: string,
 *     wrong: string,
 *     data: string,
 * }
 *
 * @psalm-type IntrusionDetectionPresentedCheck = array{
 *     id: string,
 *     category: string,
 *     internal: bool,
 *     severity: string,
 *     mode: IntrusionDetectionModeState,
 *     texts: IntrusionDetectionCheckTexts,
 *     decidesTemplate: string,
 *     decides: string,
 *     happens: list<string>,
 *     responses: list<IntrusionDetectionCheckResponse>,
 *     params: list<IntrusionDetectionParam>,
 *     cost: array{class: string, text: string},
 *     requirements: list<IntrusionDetectionRequirement>,
 *     stores: list<string>,
 *     sendsData: bool,
 *     actsWhileLearning: bool,
 *     simulatable: bool,
 * }
 *
 * @psalm-type IntrusionDetectionCheckStats = array{
 *     days: int,
 *     detections: int,
 *     enforced: int,
 *     observed: int,
 *     addressesBlocked: int,
 * }
 *
 * @psalm-type IntrusionDetectionCheck = IntrusionDetectionPresentedCheck&array{
 *     stats: IntrusionDetectionCheckStats,
 * }
 *
 * @psalm-type IntrusionDetectionCategory = array{
 *     id: string,
 *     name: string,
 * }
 *
 * @psalm-type IntrusionDetectionCheckList = array{
 *     checks: list<IntrusionDetectionCheck>,
 *     categories: list<IntrusionDetectionCategory>,
 * }
 *
 * @psalm-type IntrusionDetectionProtectionLevel = array{
 *     level: 'recommended'|'strict'|'relaxed'|'custom',
 * }
 *
 * @psalm-type IntrusionDetectionProtectionLevelChange = array{
 *     level: 'recommended'|'strict'|'relaxed'|'custom',
 *     checks: IntrusionDetectionCheckList,
 * }
 *
 * @psalm-type IntrusionDetectionLearning = array{
 *     active: bool,
 *     until: int,
 *     daysLeft: int,
 *     minDays: int,
 *     maxDays: int,
 * }
 *
 * @psalm-type IntrusionDetectionProblem = array{
 *     id: string,
 *     level: 'info'|'warning'|'error',
 *     title: string,
 *     text: string,
 *     fix?: string,
 *     url: ?string,
 *     urlLabel: ?string,
 * }
 *
 * @psalm-type IntrusionDetectionCategoryCount = array{
 *     id: string,
 *     name: string,
 *     enforced: int,
 *     observed: int,
 * }
 *
 * @psalm-type IntrusionDetectionCost = array{
 *     samples: int,
 *     averageMicroseconds: float,
 *     maxMicroseconds: int,
 * }
 *
 * @psalm-type IntrusionDetectionStatus = array{
 *     state: 'protecting'|'learning'|'off',
 *     learning: IntrusionDetectionLearning,
 *     checks: array{protect: int, observe: int, off: int},
 *     last24h: array{
 *         detections: int,
 *         enforced: int,
 *         observed: int,
 *         blockedAddresses: int,
 *         wouldHaveBlocked: int,
 *         accounts: int,
 *         categories: list<IntrusionDetectionCategoryCount>,
 *     },
 *     activeBans: int,
 *     prerequisites: array{memoryCache: 'distributed'|'local'|'none', mail: bool},
 *     cost: ?IntrusionDetectionCost,
 *     costSampleRate: int,
 *     problems: list<IntrusionDetectionProblem>,
 *     extensions: array<string, array<string, mixed>>,
 * }
 *
 * @psalm-type IntrusionDetectionDetection = array{
 *     id: int,
 *     checkId: string,
 *     checkName: string,
 *     category: string,
 *     severity: string,
 *     enforced: bool,
 *     ip: ?string,
 *     netKey: ?string,
 *     uid: ?string,
 *     shareId: ?int,
 *     hits: int,
 *     createdAt: int,
 *     lastSeenAt: int,
 *     userVerdict: ?string,
 * }
 *
 * @psalm-type IntrusionDetectionDetectionList = array{
 *     detections: list<IntrusionDetectionDetection>,
 *     hasMore: bool,
 * }
 *
 * @psalm-type IntrusionDetectionNarrative = array{
 *     title: string,
 *     happened: list<string>,
 *     done: list<string>,
 *     observedBecause: ?string,
 * }
 *
 * @psalm-type IntrusionDetectionAttempt = array{
 *     kind: string,
 *     label: string,
 *     uid: ?string,
 *     createdAt: int,
 * }
 *
 * @psalm-type IntrusionDetectionBan = array{
 *     id: int,
 *     reference: string,
 *     cidr: string,
 *     scope: string,
 *     level: int,
 *     checkId: string,
 *     checkName: string,
 *     detectionId: ?int,
 *     createdBy: ?string,
 *     note: ?string,
 *     createdAt: int,
 *     expiresAt: int,
 *     liftedAt: ?int,
 *     liftedBy: ?string,
 *     liftNote: ?string,
 *     active: bool,
 * }
 *
 * @psalm-type IntrusionDetectionBanList = array{
 *     bans: list<IntrusionDetectionBan>,
 *     hasMore: bool,
 *     activeCount: int,
 * }
 *
 * @psalm-type IntrusionDetectionAction = array{
 *     type: string,
 *     enforced: bool,
 *     note: ?string,
 * }
 *
 * @psalm-type IntrusionDetectionRiskPart = array{
 *     fact: string,
 *     label: string,
 *     points: int,
 * }
 *
 * @psalm-type IntrusionDetectionRiskLimit = array{
 *     param: string,
 *     label: string,
 *     plain: int,
 *     effective: int,
 * }
 *
 * @psalm-type IntrusionDetectionRisk = array{
 *     score: int,
 *     tier: string,
 *     tierLabel: string,
 *     tierElevated: int,
 *     tierHigh: int,
 *     parts: list<IntrusionDetectionRiskPart>,
 *     lowered: list<IntrusionDetectionRiskLimit>,
 * }
 *
 * @psalm-type IntrusionDetectionDetectionDetail = array{
 *     detection: IntrusionDetectionDetection,
 *     explanation: array<string, mixed>,
 *     actions: list<IntrusionDetectionAction>,
 *     narrative: IntrusionDetectionNarrative,
 *     text: string,
 *     attemptsAvailable: bool,
 *     attempts: list<IntrusionDetectionAttempt>,
 *     bans: list<IntrusionDetectionBan>,
 *     risk: ?IntrusionDetectionRisk,
 * }
 *
 * @psalm-type IntrusionDetectionLookup = array{
 *     kind: 'reference'|'address'|'user'|'none',
 *     query: string,
 *     bans: list<IntrusionDetectionBan>,
 *     detections: list<IntrusionDetectionDetection>,
 *     user: ?array{uid: string, displayName: string},
 * }
 *
 * @psalm-type IntrusionDetectionGlobalSetting = array{
 *     name: string,
 *     type: string,
 *     default: int|float|bool|string|list<string>,
 *     min: int|float|null,
 *     max: int|float|null,
 *     choices: list<string>,
 *     value: int|float|bool|string|list<string>,
 *     label: string,
 *     help: string,
 *     unit: string,
 *     group: string,
 * }
 *
 * @psalm-type IntrusionDetectionSettings = array{
 *     settings: list<IntrusionDetectionGlobalSetting>,
 *     templates: array<string, string>,
 * }
 *
 * @psalm-type IntrusionDetectionDay = array{
 *     day: string,
 *     start: int,
 *     enforced: int,
 *     observed: int,
 *     categories: array<string, array{enforced: int, observed: int}>,
 * }
 *
 * @psalm-type IntrusionDetectionDailyStats = array{
 *     days: list<IntrusionDetectionDay>,
 *     timezone: string,
 * }
 *
 * @psalm-type IntrusionDetectionExport = array{
 *     format: string,
 *     version: string,
 *     exportedAt: int,
 *     settings: array<string, int|float|bool|string|list<string>>,
 *     checks: array<string, array{mode: string, responses: list<string>, params: array<string, int|float|bool|string|list<string>>}>,
 * }
 *
 * @psalm-type IntrusionDetectionError = array{
 *     message: string,
 *     param: ?string,
 *     reason: string,
 * }
 *
 * @psalm-type IntrusionDetectionDigestRecipient = array{
 *     uid: string,
 *     displayName: string,
 * }
 *
 * @psalm-type IntrusionDetectionDigestLast = array{
 *     period: int,
 *     sentAt: int,
 *     result: string,
 *     recipients: int,
 *     failed: int,
 * }
 *
 * @psalm-type IntrusionDetectionDigest = array{
 *     frequency: string,
 *     sendQuiet: bool,
 *     timezone: string,
 *     nextDue: ?int,
 *     last: ?IntrusionDetectionDigestLast,
 *     recipients: int,
 *     withoutEmail: list<IntrusionDetectionDigestRecipient>,
 *     withoutEmailCount: int,
 *     mailConfigured: bool,
 *     viewerHasEmail: bool,
 * }
 *
 * @psalm-type IntrusionDetectionMessage = array{
 *     message: string,
 * }
 *
 * @psalm-type IntrusionDetectionWebhookEvent = array{
 *     class: string,
 *     name: string,
 *     description: string,
 *     example: array<string, mixed>,
 * }
 *
 * @psalm-type IntrusionDetectionWebhookEvents = array{
 *     includeIp: bool,
 *     webhooksEnabled: bool,
 *     events: list<IntrusionDetectionWebhookEvent>,
 * }
 *
 * @psalm-type IntrusionDetectionSimulation = array{
 *     check: string,
 *     testAddress: string,
 *     mode: string,
 *     modeReason: ?string,
 *     runs: bool,
 *     acts: bool,
 *     severity: string,
 *     narrative: IntrusionDetectionNarrative,
 *     responses: list<array{type: string, text: string}>,
 * }
 *
 * @psalm-type IntrusionDetectionSnippet = array{
 *     id: string,
 *     file: string,
 *     content: string,
 * }
 *
 * @psalm-type IntrusionDetectionFirewallExport = array{
 *     directory: ?string,
 *     active: bool,
 *     formats: list<string>,
 *     files: list<string>,
 *     lastWriteAt: ?int,
 *     error: ?string,
 *     errorText: ?string,
 *     errorAt: ?int,
 *     entries: int,
 *     configKey: string,
 *     snippetsUseDirectory: bool,
 *     exampleDirectory: string,
 *     snippets: list<IntrusionDetectionSnippet>,
 * }
 *
 * @psalm-type IntrusionDetectionBlocklistDay = array{
 *     day: string,
 *     matches: int,
 *     sample: list<string>,
 * }
 *
 * @psalm-type IntrusionDetectionBlocklist = array{
 *     id: string,
 *     name: string,
 *     url: string,
 *     format: string,
 *     purpose: string,
 *     mode: ?string,
 *     enabled: bool,
 *     builtin: bool,
 *     interval: int,
 *     customInterval: bool,
 *     termsUrl: ?string,
 *     reference: ?string,
 *     ranges: int,
 *     entries: int,
 *     skipped: int,
 *     lastAttemptAt: ?int,
 *     lastSuccessAt: ?int,
 *     lastFailureAt: ?int,
 *     lastError: ?string,
 *     lastErrorText: ?string,
 *     failures: int,
 *     stale: bool,
 *     matches: list<IntrusionDetectionBlocklistDay>,
 * }
 *
 * @psalm-type IntrusionDetectionBlocklists = array{
 *     lists: list<IntrusionDetectionBlocklist>,
 *     countsMatches: bool,
 *     matchDays: int,
 *     check: array{id: string, name: string, mode: IntrusionDetectionModeState},
 *     networkCheck: array{id: string, name: string, mode: IntrusionDetectionModeState},
 *     maxLists: int,
 *     minInterval: int,
 *     maxInterval: int,
 *     formats: list<string>,
 * }
 *
 * @psalm-type IntrusionDetectionSyncResult = array{
 *     list: string,
 *     outcome: string,
 *     error: ?string,
 *     errorText: ?string,
 *     ranges: int,
 * }
 *
 * @psalm-type IntrusionDetectionDecoy = array{
 *     id: int,
 *     label: string,
 *     loginName: ?string,
 *     format: string,
 *     createdBy: ?string,
 *     createdAt: int,
 *     lastTriggeredAt: ?int,
 *     triggerCount: int,
 * }
 *
 * @psalm-type IntrusionDetectionNewDecoy = array{
 *     decoy: IntrusionDetectionDecoy,
 *     secret: string,
 * }
 *
 * @psalm-type IntrusionDetectionReservedNames = array{
 *     names: list<string>,
 *     suggestions: list<string>,
 *     collisions: list<string>,
 *     max: int,
 * }
 *
 * @psalm-type IntrusionDetectionTrapPaths = array{
 *     builtinEnabled: bool,
 *     builtin: list<array{path: string, text: string}>,
 *     autodiscover: bool,
 *     autodiscoverPath: string,
 *     custom: list<string>,
 *     max: int,
 *     snippets: list<IntrusionDetectionSnippet>,
 *     snippetsSkipped: list<string>,
 * }
 *
 * @psalm-type IntrusionDetectionTraps = array{
 *     decoys: list<IntrusionDetectionDecoy>,
 *     decoyCheck: array{id: string, name: string, mode: IntrusionDetectionModeState},
 *     reservedCheck: array{id: string, name: string, mode: IntrusionDetectionModeState},
 *     trapCheck: array{id: string, name: string, mode: IntrusionDetectionModeState},
 *     decoyCollisions: list<string>,
 *     reservedNames: IntrusionDetectionReservedNames,
 *     trapPaths: IntrusionDetectionTrapPaths,
 * }
 *
 * @psalm-type IntrusionDetectionRecipient = array{
 *     uid: string,
 *     displayName: string,
 *     hasEmail: bool,
 * }
 *
 * @psalm-type IntrusionDetectionCheckNotifications = array{
 *     id: string,
 *     name: string,
 *     category: string,
 *     mode: string,
 *     admin: bool,
 *     user: bool,
 *     adminAvailable: bool,
 *     userAvailable: bool,
 * }
 *
 * @psalm-type IntrusionDetectionNotifications = array{
 *     recipients: list<IntrusionDetectionRecipient>,
 *     recipientLimit: int,
 *     mail: bool,
 *     me: array{uid: string, email: ?string, recipient: bool},
 *     checks: list<IntrusionDetectionCheckNotifications>,
 * }
 *
 * @psalm-type IntrusionDetectionTestAlert = array{
 *     bell: bool,
 *     email: 'sent'|'no_address'|'no_mail'|'failed',
 *     address: ?string,
 * }
 *
 * @psalm-type IntrusionDetectionStoredData = array{
 *     id: string,
 *     name: string,
 *     what: string,
 *     why: string,
 *     retention: string,
 *     where: string,
 *     checks: list<string>,
 * }
 *
 * @psalm-type IntrusionDetectionOutgoingData = array{
 *     id: string,
 *     name: string,
 *     text: string,
 *     active: bool,
 *     items: list<string>,
 * }
 *
 * @psalm-type IntrusionDetectionPrivacy = array{
 *     stored: list<IntrusionDetectionStoredData>,
 *     outgoing: list<IntrusionDetectionOutgoingData>,
 *     gdpr: list<string>,
 * }
 *
 * @psalm-type IntrusionDetectionSignature = array{
 *     id: string,
 *     weight: int,
 *     scope: string,
 *     requiresOther: bool,
 *     description: string,
 *     group: 'sql'|'payload',
 *     enabled: bool,
 * }
 *
 * @psalm-type IntrusionDetectionCustomSignature = array{
 *     entry: string,
 *     id: string,
 *     weight: int,
 *     pattern: string,
 *     problem: ?string,
 *     problemText: ?string,
 * }
 *
 * @psalm-type IntrusionDetectionSignatures = array{
 *     version: int,
 *     minWeight: int,
 *     signatures: list<IntrusionDetectionSignature>,
 *     custom: list<IntrusionDetectionCustomSignature>,
 *     maxCustom: int,
 *     maxLength: int,
 *     defaultWeight: int,
 * }
 *
 * @psalm-type IntrusionDetectionSignatureMatch = array{
 *     id: string,
 *     weight: int,
 *     description: string,
 * }
 *
 * @psalm-type IntrusionDetectionPayloadForm = array{
 *     encoding: string,
 *     text: string,
 *     weight: int,
 *     matches: list<IntrusionDetectionSignatureMatch>,
 * }
 *
 * @psalm-type IntrusionDetectionPayloadValue = array{
 *     location: string,
 *     name: string,
 *     skipped: ?string,
 *     truncated: bool,
 *     normalised?: string,
 *     decoded?: list<string>,
 *     forms?: list<IntrusionDetectionPayloadForm>,
 *     weight?: int,
 *     fires?: bool,
 * }
 *
 * @psalm-type IntrusionDetectionPayloadTest = array{
 *     kind: 'url'|'value',
 *     prefilter: bool,
 *     pathExcluded: bool,
 *     minWeight: int,
 *     maxBytes: int,
 *     signaturesVersion: int,
 *     fires: bool,
 *     modes: array{anonymous: string, authenticated: string},
 *     values: list<IntrusionDetectionPayloadValue>,
 * }
 *
 * @psalm-type IntrusionDetectionApproval = array{
 *     id: int,
 *     kind: string,
 *     subject: string,
 *     requestedBy: string,
 *     group: ?string,
 *     ip: ?string,
 *     status: string,
 *     decidedBy: ?string,
 *     createdAt: int,
 *     decidedAt: ?int,
 *     expiresAt: int,
 * }
 *
 * @psalm-type IntrusionDetectionPersonalDetection = array{
 *     id: int,
 *     check: string,
 *     severity: string,
 *     enforced: bool,
 *     createdAt: int,
 *     lastSeenAt: int,
 *     hits: int,
 *     subject: string,
 *     happened: list<string>,
 *     when: string,
 *     done: list<string>,
 *     advice: list<string>,
 *     address: ?string,
 *     asks: bool,
 *     verdict: ?string,
 *     verdictAt: ?int,
 *     canConfirm: bool,
 * }
 *
 * @psalm-type IntrusionDetectionTrustedNetwork = array{
 *     id: int,
 *     network: string,
 *     createdAt: int,
 *     expiresAt: int,
 *     detectionId: ?int,
 * }
 *
 * @psalm-type IntrusionDetectionAnswerError = array{
 *     reason: string,
 *     message: string,
 * }
 *
 * @psalm-type IntrusionDetectionIncidentEntry = array{
 *     id: string,
 *     at: int,
 *     endsAt: ?int,
 *     kind: string,
 *     group: string,
 *     title: string,
 *     severity: ?string,
 *     enforced: ?bool,
 *     details: list<string>,
 *     done: list<string>,
 *     note: ?string,
 *     address: ?string,
 *     accounts: list<string>,
 *     ref: ?array{type: string, id: string},
 * }
 *
 * @psalm-type IntrusionDetectionIncidentSummary = array{
 *     headline: string,
 *     happened: list<string>,
 *     startedAt: ?int,
 *     foundAt: ?int,
 *     lastActivityAt: ?int,
 *     affected: list<string>,
 *     dataCategories: list<string>,
 *     dataNote: ?string,
 *     measures: list<string>,
 *     openItems: list<string>,
 *     counts: array{entries: int, detections: int, enforced: int, observed: int},
 * }
 *
 * @psalm-type IntrusionDetectionIncidentReport = array{
 *     schemaVersion: int,
 *     generatedAt: int,
 *     generatedBy: string,
 *     server: string,
 *     subject: array{type: string, value: string, displayName: ?string},
 *     period: array{since: int, until: int},
 *     summary: IntrusionDetectionIncidentSummary,
 *     kinds: list<array{id: string, label: string, count: int}>,
 *     entries: list<IntrusionDetectionIncidentEntry>,
 *     notes: list<array{id: string, text: string, url: ?string, linkLabel: ?string}>,
 *     truncated: bool,
 *     maxEntries: int,
 * }
 *
 * @psalm-type IntrusionDetectionConfirmationMethod = array{
 *     id: string,
 *     name: string,
 *     description: string,
 *     state: 'on'|'off'|'unavailable',
 *     note: ?string,
 * }
 *
 * @psalm-type IntrusionDetectionConfirmationPolicy = array{
 *     id: string,
 *     label: string,
 *     why: string,
 *     default: string,
 *     outcome: string,
 *     setting: string,
 *     knownDevice: bool,
 *     knownDeviceAllowed: bool,
 * }
 *
 * @psalm-type IntrusionDetectionConfirmationOutcome = array{
 *     id: string,
 *     label: string,
 *     description: string,
 * }
 *
 * @psalm-type IntrusionDetectionLoginApproval = array{
 *     id: int,
 *     uid: string,
 *     displayName: string,
 *     ip: ?string,
 *     createdAt: int,
 *     expiresAt: int,
 *     canDecide: bool,
 * }
 *
 * @psalm-type IntrusionDetectionConfirmation = array{
 *     methods: list<IntrusionDetectionConfirmationMethod>,
 *     policies: list<IntrusionDetectionConfirmationPolicy>,
 *     outcomes: list<IntrusionDetectionConfirmationOutcome>,
 *     users: array{withoutMethod: int, active: int},
 *     admins: array{total: int, withoutEmail: int, withoutSecondFactor: int, withNeither: list<string>},
 *     approvers: int,
 *     approvals: list<IntrusionDetectionLoginApproval>,
 * }
 *
 * @psalm-type IntrusionDetectionUnconfirmableAccount = array{
 *     uid: string,
 *     displayName: string,
 *     lastLogin: int,
 *     groups: list<string>,
 *     admin: bool,
 * }
 *
 * @psalm-type IntrusionDetectionKnownDevice = array{
 *     id: int,
 *     label: string,
 *     family: string,
 *     platform: string,
 *     network: ?string,
 *     createdAt: int,
 *     lastSeenAt: int,
 *     current: bool,
 * }
 *
 * @psalm-type IntrusionDetectionLogin = array{
 *     id: int,
 *     createdAt: int,
 *     ip: ?string,
 *     network: ?string,
 *     userAgent: ?string,
 *     method: string,
 *     knownDevice: bool,
 *     confirmedBy: string,
 *     stepUp: ?string,
 *     current: bool,
 *     device: string,
 * }
 *
 * @psalm-type IntrusionDetectionFailedLoginDay = array{
 *     day: string,
 *     start: int,
 *     count: int,
 * }
 *
 * @psalm-type IntrusionDetectionFailedLogins = array{
 *     days: list<IntrusionDetectionFailedLoginDay>,
 *     total: int,
 *     places: int,
 *     placesCapped: bool,
 *     recent: list<array{address: string, lastSeenAt: int}>,
 *     timezone: string,
 * }
 *
 * @psalm-type IntrusionDetectionPersonalStatusItem = array{
 *     id: string,
 *     level: 'info'|'warning',
 *     text: string,
 *     at: ?int,
 * }
 *
 * @psalm-type IntrusionDetectionPersonalStatus = array{
 *     level: 'ok'|'info'|'warning',
 *     headline: string,
 *     items: list<IntrusionDetectionPersonalStatusItem>,
 * }
 *
 * @psalm-type IntrusionDetectionEmailHint = array{
 *     emailUrl: string,
 *     secondFactorUrl: ?string,
 * }
 *
 * @psalm-type IntrusionDetectionPersonalOverview = array{
 *     status: IntrusionDetectionPersonalStatus,
 *     failedLogins: IntrusionDetectionFailedLogins,
 *     emailHint: ?IntrusionDetectionEmailHint,
 *     timezone: string,
 * }
 *
 * @psalm-type IntrusionDetectionLoggedOutElsewhere = array{
 *     sessions: int,
 *     devices: int,
 * }
 *
 * @psalm-type IntrusionDetectionSecurityChange = array{
 *     id: int,
 *     type: string,
 *     label: string,
 *     via: string,
 *     actor: ?string,
 *     previous: ?string,
 *     new: ?string,
 *     detail: ?string,
 *     address: ?string,
 *     createdAt: int,
 * }
 *
 * @psalm-type IntrusionDetectionFailedLoginActivity = array{
 *     count: int,
 * }
 *
 * @psalm-type IntrusionDetectionPersonalActivityItem = array{
 *     id: string,
 *     kind: 'login'|'change'|'failed_logins'|'event',
 *     at: int,
 *     day: string,
 *     login: ?IntrusionDetectionLogin,
 *     change: ?IntrusionDetectionSecurityChange,
 *     failedLogins: ?IntrusionDetectionFailedLoginActivity,
 *     event: ?IntrusionDetectionPersonalDetection,
 * }
 *
 * @psalm-type IntrusionDetectionPersonalActivity = array{
 *     questions: list<IntrusionDetectionPersonalDetection>,
 *     items: list<IntrusionDetectionPersonalActivityItem>,
 *     hasMore: bool,
 *     today: string,
 *     timezone: string,
 * }
 *
 * @psalm-type IntrusionDetectionSecureAccountStep = array{
 *     id: string,
 *     done: bool,
 *     doneAt: ?int,
 *     skipped: bool,
 *     managed: bool,
 *     userConfirms: bool,
 * }
 *
 * @psalm-type IntrusionDetectionSecureAccountProgress = array{
 *     active: bool,
 *     startedAt: ?int,
 *     eventAt: ?int,
 *     reason: ?string,
 *     detectionId: ?int,
 *     closedAt: ?int,
 *     closedBy: ?string,
 *     done: int,
 *     total: int,
 *     steps: list<IntrusionDetectionSecureAccountStep>,
 * }
 *
 * @psalm-type IntrusionDetectionSecureAccountSession = array{
 *     id: int,
 *     name: string,
 *     kind: 'session'|'app_password',
 *     current: bool,
 *     lastActivity: ?int,
 *     createdAt: ?int,
 *     address: ?string,
 *     afterEvent: bool,
 * }
 *
 * @psalm-type IntrusionDetectionSecureAccountShare = array{
 *     id: string,
 *     name: string,
 *     type: 'link'|'email'|'federated',
 *     recipient: ?string,
 *     createdAt: int,
 *     hasPassword: bool,
 *     expiresAt: ?int,
 *     isFolder: bool,
 * }
 *
 * @psalm-type IntrusionDetectionSecureAccount = array{
 *     progress: IntrusionDetectionSecureAccountProgress,
 *     since: int,
 *     sessions: list<IntrusionDetectionSecureAccountSession>,
 *     changes: list<IntrusionDetectionSecurityChange>,
 *     shares: list<IntrusionDetectionSecureAccountShare>,
 *     email: ?string,
 *     canChangePassword: bool,
 *     links: array{security: string, personalInfo: string, activity: ?string, trash: ?string},
 * }
 *
 * @psalm-type IntrusionDetectionAccountGuide = array{
 *     uid: string,
 *     displayName: string,
 *     exists: bool,
 *     enabled: bool,
 *     lockedByLink: bool,
 *     canReenable: bool,
 *     progress: ?IntrusionDetectionSecureAccountProgress,
 * }
 */
class ResponseDefinitions {
}
