<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\AccountTakeover;

use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Signal\IDetector;
use OCA\IntrusionDetection\Signal\ISignal;
use OCA\IntrusionDetection\Signal\SecurityChanged;
use OCA\IntrusionDetection\Takeover\Db\SecurityChangeMapper;
use OCA\IntrusionDetection\Takeover\RiskyLogins;
use OCA\IntrusionDetection\Takeover\SecurityChangeLog;
use OCA\IntrusionDetection\Takeover\SecurityChangeType;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IRequest;
use OCP\IUserManager;

/**
 * Detects an account takeover sequence (concept section 10.14) after each
 * security change the account holder made.
 *
 * Only changes made by the account holder count (`via = self`): changes by
 * an administrator, occ, a password reset by email or the system never do.
 * It fires when one of these holds:
 *
 * - after a risky login ({@see RiskyLogins}): the changes made with that
 *   session within `window` after the login reach `min_points`;
 * - from any session: the account's changes within `window_any` reach
 *   `min_points_any`.
 *
 * Repeated firing within the window updates one detection, which runs its
 * (idempotent) responses again; a later email change can still bring the
 * lock link. Cost: one indexed query over the account's last changes.
 *
 * @template-implements IDetector<SecurityChanged>
 */
class AccountTakeoverDetector implements IDetector {
	/** At most this many changes are read and kept in the facts */
	public const MAX_CHANGES = 50;
	public const MAX_FACT_CHANGES = 20;

	public function __construct(
		private readonly CheckSettings $settings,
		private readonly SecurityChangeMapper $changes,
		private readonly RiskyLogins $riskyLogins,
		private readonly RemoteAddressResolver $addresses,
		private readonly IUserManager $userManager,
		private readonly IRequest $request,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * @param SecurityChanged $signal
	 * @return list<DetectionDraft>
	 */
	#[\Override]
	public function detect(#[\SensitiveParameter] ISignal $signal, ModeState $mode): iterable {
		$uid = $signal->uid;
		$sessionTokenId = $signal->sessionTokenId;
		$params = $this->settings->params(AccountTakeover::ID);
		$now = $this->timeFactory->getTime();
		$window = (int)$params[AccountTakeover::PARAM_WINDOW];
		$windowAny = (int)$params[AccountTakeover::PARAM_WINDOW_ANY];

		/** @var list<array{id: int, type: SecurityChangeType, points: int, at: int, session: ?int, ip: ?string, old: ?string, new: ?string}> $counted */
		$counted = [];
		foreach ($this->changes->findRecent($uid, $now - max($window, $windowAny), self::MAX_CHANGES) as $row) {
			$type = SecurityChangeType::tryFrom($row['type']);
			$param = $type?->pointsParam();
			if ($type === null || $param === null || $row['via'] !== SecurityChangeLog::VIA_SELF) {
				continue;
			}
			$points = (int)($params[$param] ?? 0);
			if ($points <= 0) {
				continue;
			}
			$counted[] = [
				'id' => $row['id'],
				'type' => $type,
				'points' => $points,
				'at' => $row['created_at'],
				'session' => $row['session_token_id'],
				'ip' => $row['ip'],
				'old' => $row['old_value_hint'],
				'new' => $row['new_value_hint'],
			];
		}
		if ($counted === []) {
			return [];
		}

		$rules = [];
		$used = [];
		$anyPoints = 0;
		foreach ($counted as $change) {
			if ($change['at'] >= $now - $windowAny) {
				$anyPoints += $change['points'];
				$used[$change['id']] = $change;
			}
		}
		if ($anyPoints >= (int)$params[AccountTakeover::PARAM_MIN_POINTS_ANY]) {
			$rules[] = AccountTakeover::RULE_ANY_SESSION;
		} else {
			$used = [];
		}

		$risky = $sessionTokenId === null ? null : $this->riskyLogins->of($uid, $sessionTokenId);
		$sessionPoints = 0;
		if ($risky !== null) {
			$inSession = array_filter($counted, static fn (array $c): bool => $c['session'] === $sessionTokenId
				&& $c['at'] >= $risky->at && $c['at'] <= $risky->at + $window);
			$sessionPoints = array_sum(array_column($inSession, 'points'));
			if ($sessionPoints >= (int)$params[AccountTakeover::PARAM_MIN_POINTS]) {
				$rules[] = AccountTakeover::RULE_RISKY_LOGIN;
				foreach ($inSession as $change) {
					$used[$change['id']] = $change;
				}
			}
		}
		if ($rules === []) {
			return [];
		}

		ksort($used);
		$used = array_values($used);
		$emailChange = null;
		foreach ($used as $change) {
			if ($change['type'] === SecurityChangeType::EmailChanged) {
				// The first change of the address: its previous address is the owner's.
				$emailChange = $change;
				break;
			}
		}
		$facts = [
			'rules' => $rules,
			'anyPoints' => $anyPoints,
			'sessionPoints' => $sessionPoints,
			'riskyLoginAt' => $risky?->at,
			'riskyLoginReason' => $risky?->reason,
			'riskyLoginPolicies' => $risky?->policies ?? [],
			'changes' => array_map(static fn (array $c): array => [
				'id' => $c['id'],
				'type' => $c['type']->value,
				'points' => $c['points'],
				'at' => $c['at'],
				'ip' => $c['ip'],
				'old' => $c['old'],
				'new' => $c['new'],
			], array_slice($used, -self::MAX_FACT_CHANGES)),
			'emailChangeId' => $emailChange !== null && $emailChange['old'] !== null ? $emailChange['id'] : null,
			'emailChangedAt' => $emailChange['at'] ?? null,
			'previousAddress' => $emailChange['old'] ?? null,
			'userHasEmail' => (string)$this->userManager->get($uid)?->getEMailAddress() !== '',
			'sessionTokenId' => $sessionTokenId,
			'first' => min(array_column($used, 'at')),
			'last' => max(array_column($used, 'at')),
		];
		return [new DetectionDraft(
			checkId: AccountTakeover::ID,
			source: $this->addresses->current(),
			uid: $uid,
			facts: $facts,
			merge: DetectionDraft::MERGE_USER,
			mergeWindow: max($window, $windowAny),
			userAgent: $this->request->getHeader('User-Agent') ?: null,
			sessionTokenId: $sessionTokenId,
		)];
	}
}
