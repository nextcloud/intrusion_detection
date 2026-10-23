<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\StepUpRefused;

use OCA\IntrusionDetection\Check\ICheck;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Confirm\StepUpReference;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\Category;
use OCA\IntrusionDetection\Definition\CheckDefinition;
use OCA\IntrusionDetection\Definition\CheckTexts;
use OCA\IntrusionDetection\Definition\CostClass;
use OCA\IntrusionDetection\Definition\DataKind;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\DetectionFacts;
use OCA\IntrusionDetection\Explain\IAsksWasThisYou;
use OCA\IntrusionDetection\Explain\IExplainsDetection;
use OCA\IntrusionDetection\Explain\IExplainsToUser;
use OCA\IntrusionDetection\Explain\UserNotice;
use OCP\IL10N;

/**
 * A login through the login form that needed extra confirmation was
 * refused, because the account has no way to confirm it and the policy of
 * a reason says so (concept section 11.5). The person was shown the
 * detection's reference ({@see StepUpReference}). Raised by the step-up
 * service.
 */
final class StepUpRefused implements ICheck, IExplainsDetection, IExplainsToUser, IAsksWasThisYou {
	public const ID = 'step_up_refused';

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
			responses: [ResponseType::NotifyAdmin, ResponseType::NotifyUser],
			defaultResponses: [ResponseType::NotifyAdmin, ResponseType::NotifyUser],
			cost: CostClass::OnLoginOnly,
			stores: [DataKind::Detections],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('Login refused: nothing could confirm it'),
				shortName: $l->t('Login refused'),
				summary: $l->t('A login needed extra confirmation, but the account has no second factor and no email address to confirm it with.'),
				detects: $l->t('Some logins need extra confirmation, for example from an address that took part in an attack: with the second factor, or with a code sent by email. When an account has neither, a setting per reason decides whether the login is refused, or allowed with a notice.'),
				decides: $l->t('Records each login that was refused because of these settings. The person sees a reference that they can give you.'),
				wrong: $l->t('A user without an email address who logs in from a network that was used for an attack. Look the reference up, then give the user a second factor or an email address, or lift the reason, such as the flag on the address or the protection of the account.'),
				data: $l->t('Detections: the account, the address and the reasons.'),
			),
			internal: true,
		);
	}

	#[\Override]
	public function asksWasThisYou(Detection $detection): bool {
		return true;
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$stored = DetectionFacts::of($detection);
		$facts = StepUpRefusedFacts::fromArray($stored->facts);
		$sentences = [
			$l->t('At %1$s %2$s logged in from %3$s with the correct password. The login needed extra confirmation, because %4$s.', [
				$this->dates->dateTime($stored->first),
				(string)$detection->getUid(),
				(string)$detection->getIp(),
				StepUpPolicy::describeAll($facts->policies, $l),
			]),
			$l->t('The account has no second factor and no email address that could confirm it, so the login was refused. The person was shown the reference %s.', [StepUpReference::of((string)$detection->getId())]),
		];
		if ($detection->getHits() > 1) {
			$sentences[] = $l->n('It was refused %n time within the hour.', 'It was refused %n times within the hour.', $detection->getHits());
		}
		return $sentences;
	}

	#[\Override]
	public function userNotice(Detection $detection, IL10N $l): UserNotice {
		$facts = StepUpRefusedFacts::fromArray(DetectionFacts::of($detection)->facts);
		return new UserNotice(
			$l->t('A login to your account was refused'),
			[
				$l->t('Someone logged in to your account with your correct password. The login needed extra confirmation because %s.', [StepUpPolicy::describeAll($facts->policies, $l)]),
				$l->t('Your account has no email address or second factor to confirm it with, so the login was refused.'),
			],
			[
				$l->t('If this was you, ask your administrator for help and give them the reference %s. With an email address or a second factor, you can confirm such logins yourself.', [StepUpReference::of((string)$detection->getId())]),
				$l->t('If it was not you, someone knows your password: change it, and answer "No, it was not me".'),
			],
		);
	}
}
