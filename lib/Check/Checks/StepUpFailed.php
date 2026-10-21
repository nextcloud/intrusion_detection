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
use OCA\IntrusionDetection\Confirm\EmailCodes;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\DetectionFacts;
use OCA\IntrusionDetection\Explain\IAsksWasThisYou;
use OCA\IntrusionDetection\Explain\IExplainsDetection;
use OCA\IntrusionDetection\Explain\IExplainsToUser;
use OCA\IntrusionDetection\Explain\TextRenderer;
use OCA\IntrusionDetection\Explain\UserNotice;
use OCP\IL10N;

/**
 * A login that needed extra confirmation was not confirmed: too many wrong
 * email codes, or no confirmation in time. Raised by the step-up service.
 *
 * Only wrong codes block the address. A login that merely timed out (or
 * whose session came back later without its confirmation) is ended and
 * reported, but its address is not blocked: the person who waits too long
 * for an email is far more often the account holder than an attacker, who
 * gains nothing by waiting.
 */
final class StepUpFailed implements ICheck, IExplainsDetection, IExplainsToUser, IAsksWasThisYou, ISelectsResponses {
	public const ID = 'step_up_failed';

	public const RULE_ATTEMPTS = 'attempts';
	public const RULE_TIMEOUT = 'timeout';
	/** The session of an unconfirmed login came back without its confirmation state */
	public const RULE_RESUMED = 'resumed';

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
			severity: Severity::High,
			params: [],
			responses: [ResponseType::Ban, ResponseType::KillSession, ResponseType::FlagSource, ResponseType::NotifyAdmin, ResponseType::NotifyUser],
			defaultResponses: [ResponseType::Ban, ResponseType::KillSession, ResponseType::NotifyAdmin, ResponseType::NotifyUser],
			cost: CostClass::OnLoginOnly,
			stores: [DataKind::Detections],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('Login confirmation failed'),
				summary: $l->t('A login that needed extra confirmation was not confirmed.'),
				detects: $l->t('Someone logged in with the correct password, but the login needed extra confirmation, for example because it came from an address that took part in an attack. Nextcloud sent a code to the account\'s email address. Whoever entered wrong codes again and again knows the password, but cannot read the mailbox.'),
				decides: $l->t('Fires after %1$s wrong codes, or when the login was not confirmed within {step_up_session_ttl}. Only wrong codes block the address.', [(string)EmailCodes::MAX_ATTEMPTS]),
				wrong: $l->t('Someone who mistypes the code several times, or who waits too long for the email. Their login is ended and they are asked whether it was them; they can log in again. Blocking the address can be switched off for this check with occ.'),
				data: $l->t('Detections: the account, the address, why the login needed confirmation and how it failed. The code itself is never stored: only a hash of it is kept in the session until it is used or expires.'),
			),
			internal: true,
		);
	}

	#[\Override]
	public function responsesFor(DetectionDraft $draft, array $configured, array $params): array {
		if (($draft->facts['rule'] ?? null) === self::RULE_ATTEMPTS) {
			return $configured;
		}
		return array_values(array_filter($configured, static fn (ResponseType $r): bool => $r !== ResponseType::Ban && $r !== ResponseType::FlagSource));
	}

	#[\Override]
	public function asksWasThisYou(Detection $detection): bool {
		return true;
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$facts = DetectionFacts::of($detection);
		$because = StepUpPolicy::describeAll($facts->list('policies'), $l);
		$sentences = [$because === ''
			? $l->t('At %1$s %2$s logged in from %3$s with the correct password. The login needed extra confirmation.', [
				$this->dates->dateTime($facts->int('started', $facts->first)), (string)$detection->getUid(), (string)$detection->getIp(),
			])
			: $l->t('At %1$s %2$s logged in from %3$s with the correct password. The login needed extra confirmation, because %4$s.', [
				$this->dates->dateTime($facts->int('started', $facts->first)), (string)$detection->getUid(), (string)$detection->getIp(), $because,
			])];
		$sentences[] = match ($facts->string('rule')) {
			self::RULE_TIMEOUT => $l->t('It was not confirmed within %s, so the login was ended.', [TextRenderer::duration($facts->int('ttl', 900), $l)]),
			self::RULE_RESUMED => $l->t('It was never confirmed, and the session came back later through its remember-me cookie or its session token, without the confirmation. It was ended.'),
			default => $l->n('%n wrong code was entered, so the login was ended.', '%n wrong codes were entered, so the login was ended.', $facts->int('attempts')),
		};
		return $sentences;
	}

	#[\Override]
	public function userNotice(Detection $detection, IL10N $l): UserNotice {
		$facts = DetectionFacts::of($detection);
		$because = StepUpPolicy::describeAll($facts->list('policies'), $l);
		$message = [match ($facts->string('rule')) {
			self::RULE_ATTEMPTS => $l->t('Someone logged in to your account with your correct password, but entered the wrong code again and again when asked to confirm it.'),
			default => $l->t('Someone logged in to your account with your correct password, but did not confirm the login with the code sent to your email address in time.'),
		}];
		$message[] = $because === ''
			? $l->t('The login was ended.')
			: $l->t('The login needed the extra confirmation because %s. It was ended.', [$because]);
		return new UserNotice(
			$l->t('A login to your account was not confirmed'),
			$message,
			[
				$l->t('If this was you, just log in again.'),
				$l->t('If it was not you, someone knows your password: change it, and answer "No, it was not me".'),
			],
		);
	}
}
