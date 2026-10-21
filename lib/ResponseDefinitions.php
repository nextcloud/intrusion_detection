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
 */
class ResponseDefinitions {
}
