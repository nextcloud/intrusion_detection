<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks;

use OCA\IntrusionDetection\Check\ICheck;
use OCA\IntrusionDetection\Check\ISelectsResponses;
use OCA\IntrusionDetection\Check\ISimulatable;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\Category;
use OCA\IntrusionDetection\Definition\CheckDefinition;
use OCA\IntrusionDetection\Definition\CheckTexts;
use OCA\IntrusionDetection\Definition\CostClass;
use OCA\IntrusionDetection\Definition\DataKind;
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
use OCA\IntrusionDetection\Explain\IAsksWasThisYou;
use OCA\IntrusionDetection\Explain\IExplainsDetection;
use OCA\IntrusionDetection\Explain\IExplainsToUser;
use OCA\IntrusionDetection\Explain\TextRenderer;
use OCA\IntrusionDetection\Explain\UserNotice;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\IL10N;

/**
 * One password tried against many accounts, from any number of addresses.
 * The detector is {@see PasswordSprayingDetector}.
 *
 * A successful login with a flagged password is a detection of its own
 * (rule `login_success`) with its own responses: the login needs extra
 * confirmation, the user is told and must choose a new password. The
 * failure rules only block and flag.
 */
final class PasswordSpraying implements ICheck, IExplainsDetection, ISimulatable, ISelectsResponses, IExplainsToUser, IAsksWasThisYou {
	public const ID = 'password_spraying';

	public const RULE_SPRAY = 'spray';
	public const RULE_FLAGGED = 'flagged_password';
	/** A successful login with a flagged password */
	public const RULE_LOGIN = 'login_success';

	/** The responses of the failure rules */
	public const FAILURE_RESPONSES = [ResponseType::Ban, ResponseType::FlagPassword, ResponseType::NotifyAdmin];
	/** The responses of a successful login with a flagged password */
	public const LOGIN_RESPONSES = [ResponseType::StepUp, ResponseType::ForcePasswordChange, ResponseType::NotifyAdmin, ResponseType::NotifyUser];

	/** One detection blocks at most this many addresses; the others are counted */
	public const MAX_BAN_TARGETS = 500;
	/** Another address is only blocked when it tried the password for this many accounts */
	public const MIN_NAMES_TO_BLOCK = 2;

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
				new ParamDefinition('min_names', ParamType::Int, 5, min: 3, max: 1000, preset: ParamPreset::Limit),
			],
			responses: [ResponseType::Ban, ResponseType::FlagPassword, ResponseType::StepUp, ResponseType::ForcePasswordChange, ResponseType::NotifyAdmin, ResponseType::NotifyUser],
			defaultResponses: [ResponseType::Ban, ResponseType::FlagPassword, ResponseType::StepUp, ResponseType::ForcePasswordChange, ResponseType::NotifyAdmin, ResponseType::NotifyUser],
			cost: CostClass::OnFailureOnly,
			stores: [DataKind::FailedAttempts, DataKind::Flags, DataKind::Detections, DataKind::Bans],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('Password spraying'),
				shortName: $l->t('Password spraying'),
				summary: $l->t('One password is tried against many different accounts.'),
				detects: $l->t('Instead of trying many passwords for one account, attackers try one common password, such as "Summer2026!", against every account they know. They use many addresses, so that no address and no account sees more than a failure or two.'),
				decides: $l->t('Fires when the same password fails for at least {min_names} different accounts within {window}, no matter from how many addresses. Blocking blocks the address of that failure and every address that tried the password for at least 2 accounts itself; addresses that try the password later, while it is marked, are blocked once they tried it for 2 accounts. A successful login with that password while it is marked fires again for that account: blocking and marking apply to the failures, extra confirmation, the user notice and the new password to the successful login.'),
				wrong: $l->t('Several people who were all given the same initial password and mistype it, or a shared device with an old saved password. Successful logins with the password need confirmation and a new password; nobody who knows their own password is locked out.'),
				data: $l->t('Failed logins: the address, a fingerprint of the account name and of the password, and the time, deleted after 1 hour. The password itself is never stored. When this check fires, the password fingerprint is kept for at most a day, so that logins with it need confirmation.'),
				params: [
					'window' => new ParamText($l->t('Time window'), $l->t('How far back failed logins with the same password are counted.')),
					'min_names' => new ParamText($l->t('Different accounts'), $l->t('That one password failed for within the time window.'), $l->t('accounts')),
				],
			),
			simulatable: true,
		);
	}

	#[\Override]
	public function responsesFor(DetectionDraft $draft, array $configured, array $params): array {
		$allowed = ($draft->facts['rule'] ?? null) === self::RULE_LOGIN ? self::LOGIN_RESPONSES : self::FAILURE_RESPONSES;
		return array_values(array_filter($configured, static fn (ResponseType $r): bool => in_array($r, $allowed, true)));
	}

	#[\Override]
	public function asksWasThisYou(Detection $detection): bool {
		return DetectionFacts::of($detection)->string('rule') === self::RULE_LOGIN;
	}

	#[\Override]
	public function userNotice(Detection $detection, IL10N $l): UserNotice {
		$forced = false;
		foreach ($detection->getActionList() as $action) {
			if ($action['type'] === ResponseType::ForcePasswordChange->value && $action['enforced']) {
				$forced = true;
			}
		}
		return new UserNotice(
			$l->t('Your password is on attackers\' lists'),
			[
				$l->t('Someone logged in to your account with a password that attackers are trying against many accounts on this server right now.'),
				$l->t('That does not mean that Nextcloud leaked it: attackers try common passwords and passwords stolen from other websites. But they know this one.'),
			],
			[
				$forced
					? $l->t('You will be asked to choose a new password. Choose one that you use nowhere else.')
					: $l->t('Change your password to one that you use nowhere else.'),
				$l->t('If the login was not you, also answer "No, it was not me".'),
			],
		);
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$facts = DetectionFacts::of($detection);
		if ($facts->string('rule') === self::RULE_LOGIN) {
			$sentences = [$facts->bool('client')
				? $l->t('At %1$s an app or script logged in as %2$s from %3$s with a password that is being tried against many accounts right now.', [$this->dates->dateTime($facts->first), (string)$detection->getUid(), (string)$detection->getIp()])
				: $l->t('At %1$s %2$s logged in from %3$s with a password that is being tried against many accounts right now.', [$this->dates->dateTime($facts->first), (string)$detection->getUid(), (string)$detection->getIp()])];
			if ($detection->getHits() > 1) {
				$sentences[] = $l->n('It logged in with it %n time within the hour.', 'It logged in with it %n times within the hour.', $detection->getHits());
			}
			$sentences[] = $l->t('Attackers know this password, so the account holder must confirm such logins and choose a new one.');
			return $sentences;
		}
		if ($facts->string('rule') === self::RULE_FLAGGED) {
			$names = $facts->int('names');
			return [$names > 0
				? $l->t('The address %1$s tried a password that is being tried against many accounts right now, for %2$s accounts itself, so it was treated as part of that attack.', [(string)$detection->getIp(), (string)$names])
				: $l->t('The address %s tried a password that is being tried against many accounts right now, so it was treated as part of that attack at once.', [(string)$detection->getIp()])];
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
			TextRenderer::duration($facts->threshold('window', 3600), $l),
		]);
		$listed = $facts->int('listed', $facts->int('banTargets'));
		$spared = $listed - $facts->int('banTargets');
		if ($spared > 0) {
			$sentences[] = $l->n(
				'%n address tried it for only one account and was not blocked: that may be a person who mistyped.',
				'%n addresses tried it for only one account each and were not blocked: those may be people who mistyped.',
				$spared,
			);
		}
		$unbanned = $facts->int('sources') - $listed;
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
				'first' => $now - (int)($params['window'] ?? 3600) + 60,
				'last' => $now,
				'simulated' => true,
			],
			merge: DetectionDraft::MERGE_SOURCE,
		);
	}
}
