<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks;

use OCA\IntrusionDetection\Check\ICheck;
use OCA\IntrusionDetection\Check\ISimulatable;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\Category;
use OCA\IntrusionDetection\Definition\CheckDefinition;
use OCA\IntrusionDetection\Definition\CheckTexts;
use OCA\IntrusionDetection\Definition\CostClass;
use OCA\IntrusionDetection\Definition\DataKind;
use OCA\IntrusionDetection\Definition\DigestSection;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ParamDefinition;
use OCA\IntrusionDetection\Definition\ParamPreset;
use OCA\IntrusionDetection\Definition\ParamText;
use OCA\IntrusionDetection\Definition\ParamType;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\DetectionFacts;
use OCA\IntrusionDetection\Explain\IExplainsDetection;
use OCA\IntrusionDetection\Explain\IExplainsToUser;
use OCA\IntrusionDetection\Explain\TextRenderer;
use OCA\IntrusionDetection\Explain\UserNotice;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\IL10N;

/**
 * One account's password guessed from many different addresses: the botnet
 * that tries one account at one attempt per address, which neither the
 * brute-force throttle (per address) nor credential stuffing (per source)
 * sees. The detector is {@see AccountUnderAttackDetector}.
 */
final class AccountUnderAttack implements ICheck, IExplainsDetection, IExplainsToUser, ISimulatable {
	public const ID = 'account_under_attack';

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
			severity: Severity::Medium,
			params: [
				new ParamDefinition('window', ParamType::Duration, 3600, min: 300, max: 3600),
				new ParamDefinition('min_failures', ParamType::Int, 10, min: 3, max: 1000, preset: ParamPreset::Limit),
				new ParamDefinition('min_sources', ParamType::Int, 5, min: 2, max: 1000, preset: ParamPreset::Limit),
				new ParamDefinition('protect_duration', ParamType::Duration, 86400, min: 3600, max: 7 * 86400),
				new ParamDefinition('ban_min_failures', ParamType::Int, 2, min: 1, max: 100, preset: ParamPreset::Limit),
			],
			responses: [ResponseType::ProtectAccount, ResponseType::Ban, ResponseType::NotifyAdmin, ResponseType::NotifyUser],
			defaultResponses: [ResponseType::ProtectAccount, ResponseType::NotifyAdmin, ResponseType::NotifyUser],
			cost: CostClass::OnFailureOnly,
			stores: [DataKind::FailedAttempts, DataKind::Detections],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('One account attacked from many places'),
				shortName: $l->t('Account attacked'),
				summary: $l->t('One account fails to log in from many different addresses.'),
				detects: $l->t('A botnet guessing one person\'s password, each machine trying only once or twice so that no single address looks suspicious.'),
				decides: $l->t('Fires when one account has {min_failures} failed logins from at least {min_sources} different addresses within {window}. With blocking switched on, every address with at least {ban_min_failures} of these failures and at least 4 different passwords is blocked; a device that keeps sending one old password, or a person who mistypes a few times, is not.'),
				wrong: $l->t('A user whose old password is still saved in several devices on different networks. They are asked for a confirmation at their next login and can fix their devices; nothing is blocked unless you switch blocking on.'),
				data: $l->t('Failed logins: the address, a fingerprint of the account name, the account and the time, deleted after 1 hour. Protected accounts: the account and when the protection ends.'),
				params: [
					'window' => new ParamText($l->t('Time window'), $l->t('How far back failed logins of one account are counted.')),
					'min_failures' => new ParamText($l->t('Failed logins'), $l->t('For one account within the time window.'), $l->t('failures')),
					'min_sources' => new ParamText($l->t('Different addresses'), $l->t('That the failed logins come from.'), $l->t('addresses')),
					'protect_duration' => new ParamText($l->t('Extra confirmation for'), $l->t('How long every password login to the account needs confirmation after the limits were last reached.')),
					'ban_min_failures' => new ParamText($l->t('Block addresses with at least'), $l->t('Failures of this account from one address, when blocking is switched on.'), $l->t('failures')),
				],
			),
			simulatable: true,
			confirmedLoginsExempt: true,
			userAlertInterval: 86400,
			digestSection: DigestSection::Accounts,
		);
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$facts = DetectionFacts::of($detection);
		$sentences = [
			$l->t('Between %1$s and %2$s the account %3$s had %4$s failed logins from %5$s different addresses.', [
				$this->dates->dateTime($facts->first),
				$this->dates->time($facts->last),
				(string)$detection->getUid(),
				(string)$facts->int('failures'),
				(string)$facts->int('sources'),
			]),
			$l->t('The limit at that time was %1$s failures from %2$s addresses within %3$s.', [
				(string)$facts->threshold('min_failures'),
				(string)$facts->threshold('min_sources'),
				TextRenderer::duration($facts->threshold('window', 3600), $l),
			]),
		];
		if ($facts->string('lastSource') !== '') {
			$sentences[] = $l->t('The most recent attempt came from %s.', [$facts->string('lastSource')]);
		}
		return $sentences;
	}

	#[\Override]
	public function userNotice(Detection $detection, IL10N $l): UserNotice {
		$until = null;
		foreach ($detection->getActionList() as $action) {
			if ($action['type'] === ResponseType::ProtectAccount->value && $action['enforced'] && is_array($action['ref'] ?? null)) {
				$until = (int)($action['ref']['until'] ?? 0) ?: null;
			}
		}
		$message = [
			$l->t('Someone is trying to guess your password from many different places.'),
			$l->t('Your account is safe as long as your password is strong.'),
		];
		if ($until !== null) {
			$message[] = $l->t('Until %s, logins with your password need an extra confirmation. Apps and devices that use an app password keep working.', [$this->dates->dateTime($until)]);
		}
		return new UserNotice($l->t('Someone is trying to guess your password'), $message);
	}

	#[\Override]
	public function simulate(SourceKey $source, int $now, array $params): DetectionDraft {
		return new DetectionDraft(
			checkId: self::ID,
			uid: 'alice',
			facts: [
				'lastSource' => $source->ip,
				'failures' => (int)($params['min_failures'] ?? 10),
				'sources' => (int)($params['min_sources'] ?? 5),
				'first' => $now - (int)($params['window'] ?? 3600) + 60,
				'last' => $now,
				'simulated' => true,
			],
			merge: DetectionDraft::MERGE_USER,
		);
	}
}
