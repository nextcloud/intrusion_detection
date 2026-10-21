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
use OCA\IntrusionDetection\Check\ISelectsResponses;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Check\Severity;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\DetectionFacts;
use OCA\IntrusionDetection\Explain\IAsksWasThisYou;
use OCA\IntrusionDetection\Explain\IExplainsDetection;
use OCA\IntrusionDetection\Explain\IExplainsToUser;
use OCA\IntrusionDetection\Explain\UserNotice;
use OCP\IL10N;

/**
 * A login that needed extra confirmation was allowed without one, because
 * the account has no way to confirm it and the policies of its reasons
 * allow that (concept section 11.5). The policies decide the responses:
 * "allow_notify" tells the user and the administrators, and
 * "allow_force_change" requires a new password. Raised by the step-up
 * service.
 */
final class StepUpUnconfirmed implements ICheck, IExplainsDetection, IExplainsToUser, IAsksWasThisYou, ISelectsResponses {
	public const ID = 'step_up_unconfirmed';

	public function __construct(
		private readonly DateFormatter $dates,
	) {
	}

	#[\Override]
	public function definition(): CheckDefinition {
		return new CheckDefinition(
			id: self::ID,
			category: Category::Internal,
			defaultMode: Mode::Protect,
			severity: Severity::Medium,
			params: [],
			responses: [ResponseType::ForcePasswordChange, ResponseType::NotifyAdmin, ResponseType::NotifyUser],
			defaultResponses: [ResponseType::ForcePasswordChange, ResponseType::NotifyAdmin, ResponseType::NotifyUser],
			cost: CostClass::OnLoginOnly,
			stores: [DataKind::Detections],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('Login allowed without confirmation'),
				summary: $l->t('A login needed extra confirmation, nothing could confirm it, and the settings allowed it anyway.'),
				detects: $l->t('Some logins need extra confirmation: with the second factor, or with a code sent by email. When an account has neither, a setting per reason decides. For some reasons, such as a password from a data breach, the login is allowed with a notice, or a new password is required, instead of locking the person out.'),
				decides: $l->t('Records each such login. Depending on the setting of the reason, the user and the administrators are told, or a new password is required.'),
				wrong: $l->t('Nothing is refused here. If the login was not the account holder, they can answer "No, it was not me", which ends the sessions and blocks the address.'),
				data: $l->t('Detections: the account, the address and the reasons.'),
			),
			internal: true,
		);
	}

	#[\Override]
	public function responsesFor(DetectionDraft $draft, array $configured, array $params): array {
		$notify = ($draft->facts['notify'] ?? false) === true;
		$forceChange = ($draft->facts['forceChange'] ?? false) === true;
		return array_values(array_filter($configured, static fn (ResponseType $r): bool => match ($r) {
			ResponseType::ForcePasswordChange => $forceChange,
			ResponseType::NotifyAdmin, ResponseType::NotifyUser => $notify,
			default => false,
		}));
	}

	#[\Override]
	public function asksWasThisYou(Detection $detection): bool {
		return true;
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$facts = DetectionFacts::of($detection);
		$sentences = [
			$facts->bool('client')
				? $l->t('At %1$s an app or script logged in as %2$s from %3$s with the account\'s password. The login needed extra confirmation, because %4$s.', [
					$this->dates->dateTime($facts->first), (string)$detection->getUid(), (string)$detection->getIp(), StepUpPolicy::describeAll($facts->list('policies'), $l),
				])
				: $l->t('At %1$s %2$s logged in from %3$s with the correct password. The login needed extra confirmation, because %4$s.', [
					$this->dates->dateTime($facts->first), (string)$detection->getUid(), (string)$detection->getIp(), StepUpPolicy::describeAll($facts->list('policies'), $l),
				]),
			$l->t('Nothing could confirm it, and the settings for these reasons allow such logins, so it was allowed. The session counts as unconfirmed.'),
		];
		if ($detection->getHits() > 1) {
			$sentences[] = $l->n('It happened %n time.', 'It happened %n times.', $detection->getHits());
		}
		return $sentences;
	}

	#[\Override]
	public function userNotice(Detection $detection, IL10N $l): UserNotice {
		$facts = DetectionFacts::of($detection);
		return new UserNotice(
			$l->t('A login to your account could not be confirmed'),
			[
				$l->t('Someone logged in to your account with your correct password. The login needed extra confirmation because %s.', [StepUpPolicy::describeAll($facts->list('policies'), $l)]),
				$l->t('Your account has no email address or second factor to confirm it with, so the login was allowed without it.'),
			],
			[
				$l->t('If this was you, add an email address or a second factor in your settings, so that you can confirm such logins next time.'),
				$l->t('If it was not you, someone knows your password: change it, and answer "No, it was not me".'),
			],
		);
	}
}
