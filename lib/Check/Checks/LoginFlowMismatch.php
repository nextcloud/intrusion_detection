<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks;

use OCA\IntrusionDetection\Check\ICheck;
use OCA\IntrusionDetection\Check\ISelectsResponses;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\Category;
use OCA\IntrusionDetection\Definition\CheckDefinition;
use OCA\IntrusionDetection\Definition\CheckTexts;
use OCA\IntrusionDetection\Definition\CostClass;
use OCA\IntrusionDetection\Definition\DataKind;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ParamDefinition;
use OCA\IntrusionDetection\Definition\ParamType;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Explain\DetectionFacts;
use OCA\IntrusionDetection\Explain\IAsksWasThisYou;
use OCA\IntrusionDetection\Explain\IExplainsDetection;
use OCA\IntrusionDetection\Explain\IExplainsToUser;
use OCA\IntrusionDetection\Explain\TextRenderer;
use OCA\IntrusionDetection\Explain\UserNotice;
use OCA\IntrusionDetection\KnownDevice\DeviceLabel;
use OCP\IL10N;

/**
 * A "connect a device" request (login flow v2) started on one network and
 * approved on another (concept section 10.11): what a phishing link to an
 * attacker's own login request looks like. The detector is
 * {@see LoginFlowMismatchDetector}.
 */
final class LoginFlowMismatch implements ICheck, IExplainsDetection, IExplainsToUser, IAsksWasThisYou, ISelectsResponses {
	public const ID = 'login_flow_mismatch';

	public const RULE_INITIATOR_BLOCKED = 'initiator_blocked';
	public const RULE_INITIATOR_FLAGGED = 'initiator_flagged';
	public const RULE_OTHER_NETWORK = 'other_network';
	public const RULE_TOO_OLD = 'too_old';
	public const RULE_OTHER_FAMILY = 'other_family';

	#[\Override]
	public function definition(): CheckDefinition {
		return new CheckDefinition(
			id: self::ID,
			category: Category::DevicesAndSessions,
			defaultMode: Mode::Protect,
			severity: Severity::Medium,
			params: [
				// Core lets a login request live 20 minutes.
				new ParamDefinition('max_age', ParamType::Duration, 600, min: 60, max: 1200),
				new ParamDefinition('medium_revoke', ParamType::Bool, false),
			],
			responses: [ResponseType::RevokeToken, ResponseType::NotifyAdmin, ResponseType::NotifyUser],
			defaultResponses: [ResponseType::RevokeToken, ResponseType::NotifyAdmin, ResponseType::NotifyUser],
			cost: CostClass::OnLoginOnly,
			stores: [DataKind::Detections],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('Login request phishing'),
				shortName: $l->t('Login phishing'),
				summary: $l->t('A request to connect a device was started on one network and approved on another.'),
				detects: $l->t('Desktop and mobile apps connect to Nextcloud with a login request: the app opens a page, the person logs in there and approves the new device. An attacker can start such a request on their own computer and send the link to someone, for example in an email that looks official. Whoever approves it connects the attacker\'s app to their own account.'),
				decides: $l->t('Rated high when the request was started from an address that is blocked or marked as attacking. Rated medium when it was started in another network than the one it was approved from, or approved more than {max_age} after it was started: real devices are approved within a minute or two. Rated low and only recorded when one side used IPv4 and the other IPv6, which computers with both do all the time. A medium rating counts as low when the request was started in a network the person confirmed as their own. High ratings disconnect the new device at once; medium ones only when you switch that on (switched {medium_revoke}).'),
				wrong: $l->t('Someone who starts the request on their laptop at home and approves it on their phone over mobile data, or who leaves the login page open for a while. They are asked "Was this you?", and nothing is disconnected for a medium rating unless you switch it on.'),
				data: $l->t('Detections: both addresses, the age of the request, the name of the new device and the account.'),
			),
		);
	}

	#[\Override]
	public function responsesFor(DetectionDraft $draft, array $configured, array $params): array {
		return match ($draft->severity) {
			Severity::High, Severity::Critical => $configured,
			Severity::Medium => ($params['medium_revoke'] ?? false) === true
				? $configured
				: array_values(array_filter($configured, static fn (ResponseType $r): bool => $r !== ResponseType::RevokeToken)),
			default => [],
		};
	}

	#[\Override]
	public function asksWasThisYou(Detection $detection): bool {
		return $detection->getSeverity() === Severity::Medium->value;
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$facts = DetectionFacts::of($detection);
		$initiator = $facts->string('initiator');
		$granter = $facts->string('granter');
		$sentences = [$l->t('The account %1$s approved a login request for the new device "%2$s".', [(string)$detection->getUid(), $facts->string('client')])];
		$sentences[] = match ($facts->string('rule')) {
			self::RULE_INITIATOR_BLOCKED => $l->t('The request was started from %1$s, an address that was blocked at that time, and approved from %2$s.', [$initiator, $granter]),
			self::RULE_INITIATOR_FLAGGED => $l->t('The request was started from %1$s, an address that was marked as attacking at that time, and approved from %2$s.', [$initiator, $granter]),
			self::RULE_OTHER_NETWORK => $l->t('The request was started from %1$s and approved from %2$s, which is in another network.', [$initiator, $granter]),
			self::RULE_TOO_OLD => $l->t('The request was approved %1$s after it was started. The limit at that time was %2$s.', [
				TextRenderer::duration($facts->int('age'), $l),
				TextRenderer::duration($facts->threshold('max_age', 600), $l),
			]),
			default => $l->t('The request was started from %1$s and approved from %2$s. One of them is IPv4 and the other IPv6, which is normal for devices that use both, so this was only recorded.', [$initiator, $granter]),
		};
		if ($facts->string('rule') === self::RULE_TOO_OLD) {
			$sentences[] = $initiator !== ''
				? $l->t('It was started from %1$s and approved from %2$s.', [$initiator, $granter])
				: $l->t('It was approved from %s; where it was started is not known.', [$granter]);
		}
		if ($facts->bool('trusted')) {
			$sentences[] = $l->t('The request was started in a network the person confirmed as their own, so it counts as low and was only recorded.');
		}
		return $sentences;
	}

	#[\Override]
	public function userNotice(Detection $detection, IL10N $l): UserNotice {
		$facts = DetectionFacts::of($detection);
		$initiator = $facts->string('initiator');
		$granter = $facts->string('granter');
		$revoked = false;
		foreach ($detection->getActionList() as $action) {
			if ($action['type'] === ResponseType::RevokeToken->value && $action['enforced']) {
				$revoked = true;
			}
		}
		$device = DeviceLabel::describe($facts->string('client'), $l);
		$message = [$device === null
			? $l->t('A new device was connected to your account.')
			: $l->t('A new device was connected to your account: %s.', [$device])];
		$message[] = $initiator !== ''
			? $l->t('The request came from %1$s, you approved it from %2$s.', [$initiator, $granter])
			: $l->t('You approved the request from %s.', [$granter]);
		if ($facts->string('rule') === self::RULE_TOO_OLD) {
			$message[] = $l->t('It was approved %s after it was started. Real devices are usually approved within a minute or two.', [TextRenderer::duration($facts->int('age'), $l)]);
		}
		$message[] = $revoked
			? $l->t('Nextcloud disconnected the device again to be safe. If it was yours, connect it once more.')
			: $l->t('If this was not you, remove the device in your security settings and change your password.');
		return new UserNotice($l->t('A new device was connected to your account'), $message);
	}
}
