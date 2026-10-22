<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks;

use OCA\IntrusionDetection\Check\Category;
use OCA\IntrusionDetection\Check\CheckDefinition;
use OCA\IntrusionDetection\Check\CheckTexts;
use OCA\IntrusionDetection\Check\CostClass;
use OCA\IntrusionDetection\Check\DataKind;
use OCA\IntrusionDetection\Check\ICheck;
use OCA\IntrusionDetection\Check\InvalidParamException;
use OCA\IntrusionDetection\Check\ISimulatable;
use OCA\IntrusionDetection\Check\IValidatesParams;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\ParamDefinition;
use OCA\IntrusionDetection\Check\ParamText;
use OCA\IntrusionDetection\Check\ParamType;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Check\Severity;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\DetectionFacts;
use OCA\IntrusionDetection\Explain\IExplainsDetection;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Traps\AccountNames;
use OCA\IntrusionDetection\Traps\ReservedNames;
use OCP\IL10N;

/**
 * A login attempt with a reserved name, such as "admin", that no account
 * uses. Nobody who belongs here types it, so any attempt blocks the source.
 * The names are managed by {@see ReservedNames}.
 */
final class ReservedName implements ICheck, IExplainsDetection, ISimulatable, IValidatesParams {
	public const ID = 'reserved_name';

	public function __construct(
		private readonly DateFormatter $dates,
		private readonly AccountNames $accounts,
	) {
	}

	#[\Override]
	public function definition(): CheckDefinition {
		return new CheckDefinition(
			id: self::ID,
			category: Category::Traps,
			defaultMode: Mode::Protect,
			severity: Severity::Low,
			params: [
				// Empty by default; the install step reserves the suggested names that are not accounts.
				new ParamDefinition('names', ParamType::StringList, [], itemPattern: ReservedNames::NAME_PATTERN, maxItems: ReservedNames::MAX_NAMES, maxItemLength: 64),
			],
			responses: [ResponseType::Ban, ResponseType::NotifyAdmin],
			defaultResponses: [ResponseType::Ban],
			cost: CostClass::OnFailureOnly,
			stores: [DataKind::Detections, DataKind::Bans],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('Decoy admin account'),
				shortName: $l->t('Decoy admin login'),
				summary: $l->t('Someone tries to log in with a reserved name such as "admin" that no account uses.'),
				detects: $l->t('Attack tools try common account names like "admin", "root" or "test" first. If no account on your server has such a name, nobody who belongs here ever types it, so an attempt with it is a sure sign of an attacker.'),
				decides: $l->t('Fires at the first failed login with one of these names: {names}.'),
				wrong: $l->t('Someone who really has an account with that name, for example one that appeared later through LDAP. Such names are skipped automatically and shown as a problem in the setup checks.'),
				data: $l->t('Detections: the address, the reserved name that was tried, and the time.'),
				params: [
					'names' => new ParamText($l->t('Reserved names'), $l->t('Login names no account uses. Manage them on the Blocks tab.')),
				],
			),
			simulatable: true,
		);
	}

	#[\Override]
	public function validateParam(string $name, int|float|bool|string|array $value): int|float|bool|string|array {
		if ($name !== 'names' || !is_array($value)) {
			return $value;
		}
		$normalised = [];
		foreach ($value as $item) {
			$item = AccountNames::normalise($item);
			if ($this->accounts->exists($item)) {
				throw new InvalidParamException('existing_user', ['param' => $name, 'item' => $item]);
			}
			$normalised[] = $item;
		}
		return array_values(array_unique($normalised));
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$facts = DetectionFacts::of($detection);
		$sentences = [$l->t('The address %1$s tried to log in as "%2$s", a reserved name that no account uses.', [
			(string)$detection->getIp(),
			$facts->string('name'),
		])];
		if ($detection->getHits() > 1) {
			$sentences[] = $l->n('It tried %n time between %1$s and %2$s.', 'It tried %n times between %1$s and %2$s.', $detection->getHits(), [
				$this->dates->dateTime($detection->getCreatedAt()),
				$this->dates->time($detection->getLastSeenAt()),
			]);
		}
		return $sentences;
	}

	#[\Override]
	public function simulate(SourceKey $source, int $now, array $params): DetectionDraft {
		$names = is_array($params['names'] ?? null) ? $params['names'] : [];
		return new DetectionDraft(
			checkId: self::ID,
			source: $source,
			facts: ['name' => (string)($names[0] ?? 'admin'), 'simulated' => true],
			merge: DetectionDraft::MERGE_SOURCE,
		);
	}
}
