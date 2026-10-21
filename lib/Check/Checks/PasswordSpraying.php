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
use OCA\IntrusionDetection\Check\ISimulatable;
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
use OCA\IntrusionDetection\Explain\TextRenderer;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\IL10N;

/**
 * One password tried against many accounts, from any number of addresses.
 * The detector is {@see PasswordSprayingDetector}.
 */
final class PasswordSpraying implements ICheck, IExplainsDetection, ISimulatable {
	public const ID = 'password_spraying';

	public const RULE_SPRAY = 'spray';
	public const RULE_FLAGGED = 'flagged_password';

	/** One detection blocks at most this many addresses; the others are counted */
	public const MAX_BAN_TARGETS = 500;

	public function __construct(
		private readonly DateFormatter $dates,
	) {
	}

	#[\Override]
	public function definition(): CheckDefinition {
		return new CheckDefinition(
			id: self::ID,
			category: Category::LoginAttacks,
			defaultMode: Mode::Protect,
			severity: Severity::High,
			params: [
				// Attempts are kept for one hour, so the window cannot be longer.
				new ParamDefinition('window', ParamType::Duration, 3600, min: 300, max: 3600),
				new ParamDefinition('min_names', ParamType::Int, 5, min: 3, max: 1000),
			],
			responses: [ResponseType::Ban, ResponseType::FlagPassword, ResponseType::NotifyAdmin],
			defaultResponses: [ResponseType::Ban, ResponseType::FlagPassword, ResponseType::NotifyAdmin],
			cost: CostClass::OnFailureOnly,
			stores: [DataKind::FailedAttempts, DataKind::Flags, DataKind::Detections, DataKind::Bans],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('Password spraying'),
				summary: $l->t('One password is tried against many different accounts.'),
				detects: $l->t('Instead of trying many passwords for one account, attackers try one common password, such as "Summer2026!", against every account they know. They use many addresses, so that no address and no account sees more than a failure or two.'),
				decides: $l->t('Fires when the same password fails for at least {min_names} different accounts within {window}, no matter from how many addresses.'),
				wrong: $l->t('Several people who were all given the same initial password and mistype it, or a shared device with an old saved password. Successful logins with the password need confirmation; nobody who knows their own password is locked out.'),
				data: $l->t('Failed logins: the address, a fingerprint of the account name and of the password, and the time, deleted after 1 hour. The password itself is never stored. When this check fires, the password fingerprint is kept for a day, so that logins with it need confirmation.'),
				params: [
					'window' => new ParamText($l->t('Time window'), $l->t('How far back failed logins with the same password are counted.')),
					'min_names' => new ParamText($l->t('Different accounts'), $l->t('That one password failed for within the time window.'), $l->t('accounts')),
				],
			),
			simulatable: true,
		);
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$facts = DetectionFacts::of($detection);
		if ($facts->string('rule') === self::RULE_FLAGGED) {
			return [$l->t('The address %s tried a password that is being tried against many accounts right now, so it was treated as part of that attack at once.', [(string)$detection->getIp()])];
		}
		$sentences = [
			$l->t('Between %1$s and %2$s one password was tried against %3$s different accounts, from %4$s different addresses.', [
				$this->dates->dateTime($facts->first),
				$this->dates->time($facts->last),
				(string)$facts->int('names'),
				(string)$facts->int('sources'),
			]),
		];
		$targets = $facts->targetsSentence($l);
		if ($targets !== null) {
			$sentences[] = $targets;
		}
		$sentences[] = $l->t('The limit at that time was %1$s accounts within %2$s.', [
			(string)$facts->threshold('min_names'),
			TextRenderer::duration(min(3600, $facts->threshold('window', 3600)), $l),
		]);
		$unbanned = $facts->int('sources') - $facts->int('banTargets');
		if ($facts->int('banTargets') > 0 && $unbanned > 0) {
			$sentences[] = $l->n(
				'%n more address tried it, but one detection blocks at most %s addresses.',
				'%n more addresses tried it, but one detection blocks at most %s addresses.',
				$unbanned,
				[(string)self::MAX_BAN_TARGETS],
			);
		}
		$sentences[] = $l->t('The password itself is never stored. Nextcloud keeps only a keyed fingerprint of it, to recognise it again.');
		return $sentences;
	}

	#[\Override]
	public function simulate(SourceKey $source, int $now, array $params): DetectionDraft {
		$names = (int)($params['min_names'] ?? 5);
		return new DetectionDraft(
			checkId: self::ID,
			source: $source,
			facts: [
				'rule' => self::RULE_SPRAY,
				'failures' => $names,
				'names' => $names,
				'sources' => $names,
				'banTargets' => $names,
				'first' => $now - min(3600, (int)($params['window'] ?? 3600)) + 60,
				'last' => $now,
				'simulated' => true,
			],
			merge: DetectionDraft::MERGE_SOURCE,
		);
	}
}
