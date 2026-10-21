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
 *     fired: int,
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
 *     total: int,
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
 * @psalm-type IntrusionDetectionDetectionDetail = array{
 *     detection: IntrusionDetectionDetection,
 *     explanation: array<string, mixed>,
 *     actions: list<IntrusionDetectionAction>,
 *     narrative: IntrusionDetectionNarrative,
 *     text: string,
 *     attemptsAvailable: bool,
 *     attempts: list<IntrusionDetectionAttempt>,
 *     bans: list<IntrusionDetectionBan>,
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
 * @psalm-type IntrusionDetectionContributionReport = array{
 *     ip: string,
 *     check: string,
 *     first_seen: int,
 *     hits: int,
 * }
 *
 * @psalm-type IntrusionDetectionContribution = array{
 *     enabled: bool,
 *     url: string,
 *     lastAttemptAt: ?int,
 *     lastSuccessAt: ?int,
 *     lastResult: ?string,
 *     lastError: ?string,
 *     lastReports: int,
 *     texts: array{name: string, summary: string, sent: string, privacy: string, status: string},
 *     preview: array{
 *         payload: array{instance: string, version: int, reports: list<IntrusionDetectionContributionReport>},
 *         reason: ?string,
 *         windowStart: int,
 *         windowEnd: int,
 *         truncated: bool,
 *     },
 * }
 *
 * @psalm-type IntrusionDetectionPrivacy = array{
 *     stored: list<IntrusionDetectionStoredData>,
 *     outgoing: list<IntrusionDetectionOutgoingData>,
 *     contribution: ?IntrusionDetectionContribution,
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
 */
class ResponseDefinitions {
}
