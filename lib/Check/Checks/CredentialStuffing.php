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
use OCA\IntrusionDetection\Check\ParamPreset;
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
 * Many different login names failing from one address or network, or a
 * flood of failures spread thinly over many addresses (a botnet).
 * The detector is {@see CredentialStuffingDetector}.
 */
final class CredentialStuffing implements ICheck, IExplainsDetection, ISimulatable {
	public const ID = 'credential_stuffing';

	public const RULE_SOURCE = 'source';
	public const RULE_NETWORK = 'network';
	public const RULE_DISTRIBUTED = 'distributed';

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
				new ParamDefinition('window', ParamType::Duration, 600, min: 60, max: 3600),
				new ParamDefinition('min_failures', ParamType::Int, 10, min: 3, max: 1000, preset: ParamPreset::Limit),
				new ParamDefinition('min_names', ParamType::Int, 5, min: 2, max: 1000, preset: ParamPreset::Limit),
				new ParamDefinition('net_factor', ParamType::Int, 3, min: 1, max: 100),
				new ParamDefinition('distributed_min_failures', ParamType::Int, 100, min: 10, max: 100000, preset: ParamPreset::Limit),
				new ParamDefinition('distributed_min_sources', ParamType::Int, 20, min: 2, max: 10000, preset: ParamPreset::Limit),
				new ParamDefinition('distributed_min_names', ParamType::Int, 20, min: 2, max: 10000, preset: ParamPreset::Limit),
			],
			responses: [ResponseType::Ban, ResponseType::FlagSource, ResponseType::NotifyAdmin],
			defaultResponses: [ResponseType::Ban, ResponseType::FlagSource, ResponseType::NotifyAdmin],
			cost: CostClass::OnFailureOnly,
			stores: [DataKind::FailedAttempts, DataKind::Detections, DataKind::Bans, DataKind::Flags],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('Credential stuffing'),
				summary: $l->t('Many different accounts fail to log in from one address, or the whole server sees a flood of failed logins.'),
				detects: $l->t('Attackers buy long lists of usernames and passwords stolen from other websites and try them against your server, hoping that people reuse passwords. Botnets spread these attempts over thousands of addresses, so that no single address looks suspicious.'),
				decides: $l->t('Fires when one address fails to log in {min_failures} times for at least {min_names} different accounts within {window}. A whole /24 network is held to {net_factor} times these numbers: then each of its addresses that failed at least 2 times for 2 accounts is blocked, so that a neighbour who mistyped once is not. When none of them did, the attempts are spread thinly over the network, and the /24 itself is blocked, unless many people or an administrator log in from it. It also fires when the whole server sees at least {distributed_min_failures} failed logins from at least {distributed_min_sources} addresses for at least {distributed_min_names} accounts within 10 minutes, which is a botnet spreading its attempts thin. While that lasts, every address that fails 3 times for 2 accounts is blocked.'),
				wrong: $l->t('Many people behind one office address mistyping their passwords at the same time. Addresses from which several different people whose accounts are at least 3 days old logged in successfully in the last day are never blocked; you are notified instead.'),
				data: $l->t('Failed logins: the address, a fingerprint of the account name, and the time, deleted after 1 hour.'),
				params: [
					'window' => new ParamText($l->t('Time window'), $l->t('How far back failed logins are counted.')),
					'min_failures' => new ParamText($l->t('Failed logins'), $l->t('From one address within the time window.'), $l->t('failures')),
					'min_names' => new ParamText($l->t('Different accounts'), $l->t('That the address tried within the time window.'), $l->t('accounts')),
					'net_factor' => new ParamText($l->t('Network factor'), $l->t('A whole /24 network is held to this many times the numbers above.'), $l->t('times')),
					'distributed_min_failures' => new ParamText($l->t('Failed logins on the whole server'), $l->t('Within 10 minutes, for the botnet detection.'), $l->t('failures')),
					'distributed_min_sources' => new ParamText($l->t('Different addresses'), $l->t('That the failed logins on the whole server come from.'), $l->t('addresses')),
					'distributed_min_names' => new ParamText($l->t('Different accounts on the whole server'), $l->t('That the failed logins on the whole server are for.'), $l->t('accounts')),
				],
			),
			simulatable: true,
		);
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$facts = DetectionFacts::of($detection);
		$window = TextRenderer::duration($facts->threshold('window', 600), $l);
		$from = $this->dates->dateTime($facts->first);
		$to = $this->dates->time($facts->last);
		$sentences = [];

		switch ($facts->string('rule', self::RULE_SOURCE)) {
			case self::RULE_DISTRIBUTED:
				$sentences[] = $l->t('Between %1$s and %2$s the whole server saw %3$s failed logins from %4$s different addresses, trying %5$s different accounts. This is a botnet spreading its attempts thin.', [
					$from, $to, (string)$facts->int('failures'), (string)$facts->int('sources'), (string)$facts->int('names'),
				]);
				$sentences[] = $l->t('The limit at that time was %1$s failures from %2$s addresses for %3$s accounts within 10 minutes.', [
					(string)$facts->threshold('distributed_min_failures'), (string)$facts->threshold('distributed_min_sources'), (string)$facts->threshold('distributed_min_names'),
				]);
				$sentences[] = $l->t('While the attack lasts, and for an hour after it, successful logins from every address that fails need extra confirmation, and addresses that fail 3 times for 2 accounts are blocked.');
				break;
			case self::RULE_NETWORK:
				$factor = max(1, $facts->threshold('net_factor', 3));
				$sentences[] = $l->t('Between %1$s and %2$s the network %3$s failed to log in %4$s times from %5$s addresses, trying %6$s different accounts.', [
					$from, $to, $facts->string('net', (string)$detection->getNetKey()), (string)$facts->int('failures'), (string)$facts->int('sources'), (string)$facts->int('names'),
				]);
				$sentences[] = $l->t('The limit for a network at that time was %1$s failures for %2$s accounts within %3$s.', [
					(string)($facts->threshold('min_failures') * $factor), (string)($facts->threshold('min_names') * $factor), $window,
				]);
				break;
			default:
				$sentences[] = $l->t('Between %1$s and %2$s the address %3$s failed to log in %4$s times, trying %5$s different accounts.', [
					$from, $to, (string)$detection->getIp(), (string)$facts->int('failures'), (string)$facts->int('names'),
				]);
				$sentences[] = $l->t('The limit at that time was %1$s failures for %2$s accounts within %3$s.', [
					(string)$facts->threshold('min_failures'), (string)$facts->threshold('min_names'), $window,
				]);
		}
		$targets = $facts->targetsSentence($l);
		if ($targets !== null) {
			array_splice($sentences, 1, 0, [$targets]);
		}
		return $sentences;
	}

	#[\Override]
	public function simulate(SourceKey $source, int $now, array $params): DetectionDraft {
		$window = (int)($params['window'] ?? 600);
		return new DetectionDraft(
			checkId: self::ID,
			source: $source,
			facts: [
				'rule' => self::RULE_SOURCE,
				'failures' => (int)($params['min_failures'] ?? 10),
				'names' => (int)($params['min_names'] ?? 5),
				'sources' => 1,
				'first' => $now - $window + 60,
				'last' => $now,
				'simulated' => true,
			],
			merge: DetectionDraft::MERGE_SOURCE,
		);
	}
}
