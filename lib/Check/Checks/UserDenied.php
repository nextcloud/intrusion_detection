<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks;

use OCA\IntrusionDetection\Admin\CheckNames;
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
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\DetectionFacts;
use OCA\IntrusionDetection\Explain\IExplainsDetection;
use OCA\IntrusionDetection\Explain\IExplainsToUser;
use OCA\IntrusionDetection\Explain\TextRenderer;
use OCA\IntrusionDetection\Explain\UserNotice;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCP\IL10N;

/**
 * A user answered "No, it was not me" about one of their detections
 * (concept section 11.8). The answer acts even in learning mode: it is the
 * account holder's own decision. Raised by the "Was this you?" service.
 */
final class UserDenied implements ICheck, IExplainsDetection, IExplainsToUser, ISelectsResponses {
	public const ID = 'user_denied';

	public function __construct(
		private readonly DateFormatter $dates,
		private readonly CheckNames $names,
	) {
	}

	#[\Override]
	public function definition(): CheckDefinition {
		return new CheckDefinition(
			id: self::ID,
			category: Category::Internal,
			defaultMode: Mode::Protect,
			severity: Severity::High,
			params: [],
			responses: [ResponseType::Ban, ResponseType::RevokeToken, ResponseType::KillSession, ResponseType::ForcePasswordChange, ResponseType::NotifyAdmin],
			defaultResponses: [ResponseType::Ban, ResponseType::RevokeToken, ResponseType::KillSession, ResponseType::ForcePasswordChange, ResponseType::NotifyAdmin],
			cost: CostClass::OnLoginOnly,
			stores: [DataKind::Detections, DataKind::Bans, DataKind::Flags],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('A user said it was not them'),
				shortName: $l->t('User said "not me"'),
				summary: $l->t('A user answered "No, it was not me" about a security event of their account.'),
				detects: $l->t('Users are asked "Was this you?" about logins and other events that may have been someone else. When they answer no, someone else has used their account or their password.'),
				decides: $l->t('Ends the sessions and app passwords linked to the event, requires a new password when the event involved the password, blocks the address at the second level unless the answer comes from that very address, and marks its network, so that logins from there need extra confirmation for %s. When the answer comes from a session whose login proved no more than the password, or from a Nextcloud app with its app password, it only tells the administrators, and the question stays open until the user answers after a login that proved more.', [TextRenderer::duration(FlaggedSources::DURATION, $l)]),
				wrong: $l->t('A user who does not recognise their own login, for example from a new phone. They lose that session and log in again. Lift the block if needed.'),
				data: $l->t('Detections: the account, the event the answer was about and what was done.'),
			),
			internal: true,
		);
	}

	/**
	 * A new password only when the password was involved. No block when the
	 * answer comes from the very address of the event: that would lock out
	 * the person who answers. From a session whose login proved no more than
	 * the password, only the administrators are told: whoever has the
	 * password could have answered.
	 */
	#[\Override]
	public function responsesFor(DetectionDraft $draft, array $configured, array $params): array {
		$password = ($draft->facts['passwordInvolved'] ?? false) === true;
		$fromSource = ($draft->facts['answeredFromSource'] ?? false) === true;
		if (($draft->facts['weakSession'] ?? false) === true) {
			return in_array(ResponseType::NotifyAdmin, $configured, true) ? [ResponseType::NotifyAdmin] : [];
		}
		return array_values(array_filter($configured, static fn (ResponseType $r): bool => match ($r) {
			ResponseType::ForcePasswordChange => $password,
			ResponseType::Ban => !$fromSource,
			default => true,
		}));
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$facts = DetectionFacts::of($detection);
		$sentences = [$l->t('%1$s answered "No, it was not me" about detection %2$s (%3$s, at %4$s).', [
			(string)$detection->getUid(),
			(string)$facts->int('detection'),
			$this->names->name($facts->string('check'), $l),
			$this->dates->dateTime($facts->int('detectedAt', $detection->getCreatedAt())),
		])];
		if ($facts->bool('weakSession')) {
			$sentences[] = $l->t('The answer came from a session whose login proved no more than the password, or from a Nextcloud app with its app password, so nothing was ended or blocked, and the question stays open for the user. Check with the user that they answered themselves.');
		}
		$network = $facts->string('network');
		if ($network !== '') {
			$sentences[] = $l->t('Logins from the network %s need extra confirmation for a while.', [$network]);
		}
		return $sentences;
	}

	#[\Override]
	public function userNotice(Detection $detection, IL10N $l): UserNotice {
		$facts = DetectionFacts::of($detection);
		return new UserNotice(
			$l->t('You said it was not you'),
			[
				$l->t('You answered "No, it was not me" about an event on your account at %s.', [$this->dates->dateTime($facts->int('detectedAt', $detection->getCreatedAt()))]),
			],
			[
				$l->t('Check your devices and sessions in your security settings, and change your password if you have not been asked to already.'),
			],
		);
	}
}
