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
 * Abuse of "Forgot password" (concept section 10.10): one address trying
 * many names to find accounts, or one account flooded with reset emails.
 * The detector is {@see ResetProbingDetector}.
 */
final class ResetProbing implements ICheck, IExplainsDetection, IExplainsToUser, ISimulatable, ISelectsResponses {
	public const ID = 'reset_probing';

	public const RULE_ENUMERATION = 'enumeration';
	public const RULE_FLOOD = 'flood';

	private const ENUMERATION_RESPONSES = [ResponseType::Ban];
	private const FLOOD_RESPONSES = [ResponseType::SuppressResetMail, ResponseType::NotifyUser, ResponseType::NotifyAdmin];

	public function __construct(
		private readonly DateFormatter $dates,
	) {
	}

	#[\Override]
	public function definition(): CheckDefinition {
		return new CheckDefinition(
			id: self::ID,
			category: Category::SharesAndReset,
			defaultMode: Mode::Protect,
			severity: Severity::Medium,
			params: [
				new ParamDefinition('enum_min_inputs', ParamType::Int, 5, min: 3, max: 1000, preset: ParamPreset::Limit),
				new ParamDefinition('enum_window', ParamType::Duration, 600, min: 60, max: 3600),
				new ParamDefinition('flood_min_requests', ParamType::Int, 5, min: 3, max: 1000, preset: ParamPreset::Limit),
				new ParamDefinition('flood_window', ParamType::Duration, 3600, min: 300, max: 3600),
				new ParamDefinition('suppress_duration', ParamType::Duration, 3600, min: 600, max: 86400),
			],
			responses: [ResponseType::Ban, ResponseType::SuppressResetMail, ResponseType::NotifyAdmin, ResponseType::NotifyUser],
			defaultResponses: [ResponseType::Ban, ResponseType::SuppressResetMail, ResponseType::NotifyAdmin, ResponseType::NotifyUser],
			cost: CostClass::OnFailureOnly,
			stores: [DataKind::FailedAttempts, DataKind::Detections, DataKind::Bans, DataKind::ResetSuppressions],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('Password reset abuse'),
				shortName: $l->t('Password reset abuse'),
				summary: $l->t('Someone uses "Forgot password" to find accounts, or floods one person with reset emails.'),
				detects: $l->t('The "Forgot password" form gives the same answer whether an account exists or not, but attackers still use it. They try many names to find out which accounts exist, or send one person so many reset emails that the person gets annoyed, misses a real one, or clicks one they did not ask for.'),
				decides: $l->t('Fires when one address asks for password resets for {enum_min_inputs} different names or email addresses within {enum_window}; the address is blocked. It also fires when one account is asked for {flood_min_requests} reset emails within {flood_window}, from any number of addresses: then no reset emails are sent to it for {suppress_duration} after the last request, for at most a day within two days, and the person is told once, with the latest time the emails are held back.'),
				wrong: $l->t('Someone who does not remember their login name and tries a few variants; it takes several different ones to fire. A person who asks for many reset emails because none arrives: they get no further emails for a while and are told why. The answer on the page is always the same, so nobody learns whether an email was sent.'),
				data: $l->t('Reset requests: the address, a fingerprint of what was typed (never the text itself), the account if it matches one, and the time, deleted after 1 hour. Accounts whose reset emails are held back: the account, since and until when, kept for two days.'),
			),
			simulatable: true,
		);
	}

	#[\Override]
	public function responsesFor(DetectionDraft $draft, array $configured, array $params): array {
		$allowed = ($draft->facts['rule'] ?? null) === self::RULE_FLOOD ? self::FLOOD_RESPONSES : self::ENUMERATION_RESPONSES;
		return array_values(array_filter($configured, static fn (ResponseType $r): bool => in_array($r, $allowed, true)));
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$facts = DetectionFacts::of($detection);
		$from = $this->dates->dateTime($facts->first);
		$to = $this->dates->time($facts->last);
		$sentences = [];
		if ($facts->string('rule') === self::RULE_FLOOD) {
			$sentences[] = $l->t('Between %1$s and %2$s someone asked %3$s times for password reset emails for the account %4$s, from %5$s different addresses.', [
				$from, $to, $facts->estimated('requests', $l), (string)$detection->getUid(), (string)$facts->int('sources'),
			]);
			$sentences[] = $l->t('The limit at that time was %1$s requests for one account within %2$s.', [
				(string)$facts->threshold('flood_min_requests'),
				TextRenderer::duration($facts->threshold('flood_window', 3600), $l),
			]);
			if ($facts->string('lastSource') !== '') {
				$sentences[] = $l->t('The most recent request came from %s.', [$facts->string('lastSource')]);
			}
		} else {
			$sentences[] = $l->t('Between %1$s and %2$s the address %3$s asked for password resets for %4$s different names or email addresses (%5$s requests).', [
				$from, $to, (string)$detection->getIp(), $facts->estimated('inputs', $l), $facts->estimated('requests', $l),
			]);
			$targets = $facts->targetsSentence($l);
			if ($targets !== null) {
				$sentences[] = $targets;
			}
			$sentences[] = $l->t('The limit at that time was %1$s different names or addresses within %2$s.', [
				(string)$facts->threshold('enum_min_inputs'),
				TextRenderer::duration($facts->threshold('enum_window', 600), $l),
			]);
		}
		$factor = $facts->int('sampleFactor', 1);
		if ($factor > 1) {
			$sentences[] = $l->t('The server was receiving so many failed attempts that only one in %s reset requests was recorded. The numbers are estimates from those.', [(string)$factor]);
		}
		return $sentences;
	}

	#[\Override]
	public function userNotice(Detection $detection, IL10N $l): UserNotice {
		$facts = DetectionFacts::of($detection);
		$until = null;
		$latest = null;
		foreach ($detection->getActionList() as $action) {
			if ($action['type'] === ResponseType::SuppressResetMail->value && $action['enforced'] && is_array($action['ref'] ?? null)) {
				$until = (int)($action['ref']['until'] ?? 0) ?: null;
				$latest = (int)($action['ref']['latest'] ?? 0) ?: null;
			}
		}
		$message = [
			$l->n(
				'Someone asked for password reset emails for your account %n time within %1$s.',
				'Someone asked for password reset emails for your account %n times within %1$s.',
				$facts->int('requests'),
				[TextRenderer::duration($facts->threshold('flood_window', 3600), $l)],
			),
		];
		if ($until !== null) {
			$message[] = $l->t('Nextcloud stopped sending them until %s.', [$this->dates->dateTime($until)]);
			if ($latest !== null && $latest > $until) {
				$message[] = $l->t('If someone keeps asking, they stay held back until %s at the latest, never longer.', [$this->dates->dateTime($latest)]);
			}
		}
		$message[] = $l->t('Your password has not been changed.');
		$message[] = $until !== null
			? $l->t('If it was you, wait until then and try again.')
			: $l->t('If it was not you, ignore these emails: nobody can use them without access to your mailbox.');
		return new UserNotice($l->t('Someone asked for many password reset emails for your account'), $message);
	}

	#[\Override]
	public function simulate(SourceKey $source, int $now, array $params): DetectionDraft {
		$inputs = (int)($params['enum_min_inputs'] ?? 5);
		return new DetectionDraft(
			checkId: self::ID,
			source: $source,
			facts: [
				'rule' => self::RULE_ENUMERATION,
				'inputs' => $inputs,
				'requests' => $inputs,
				'sampleFactor' => 1,
				'targets' => ['alice'],
				'first' => $now - (int)($params['enum_window'] ?? 600) + 60,
				'last' => $now,
				'simulated' => true,
			],
			merge: DetectionDraft::MERGE_SOURCE,
		);
	}
}
