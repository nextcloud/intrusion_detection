<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\LoginFlowMismatch;

use OCA\IntrusionDetection\Address\AddressResolver;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Detection\Explanation;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\TrustedNetwork\ITrustedNetworks;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\Token\IToken;

/**
 * Judges a granted login flow v2 request (concept section 10.11). The first
 * rule that applies decides:
 *
 * 1. high: the address that started it is blocked or flagged;
 * 2. medium: it was started and approved in different networks of the same
 *    IP family (/24, /64);
 * 3. medium: it was approved more than `max_age` after it was started;
 * 4. low, recorded only: the two addresses are of different IP families.
 *
 * Medium becomes low when the starting network is one of the user's trusted
 * networks. A flow started from an allowlisted address, loopback or the
 * server itself is not judged.
 */
class LoginFlowMismatchDetector {
	public function __construct(
		private readonly CheckSettings $settings,
		private readonly ResponseEngine $engine,
		private readonly LoginFlowMismatch $check,
		private readonly AddressResolver $addressResolver,
		private readonly FlaggedSources $flags,
		private readonly RemoteAddressResolver $addresses,
		private readonly ITrustedNetworks $trustedNetworks,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	public function granted(IToken $token, ?string $initiatorIp, int $startedAt, SourceKey $granter, ?string $userAgent): void {
		if (!$this->settings->modeState(LoginFlowMismatch::ID)->runs()) {
			return;
		}
		$initiator = $initiatorIp === null ? null : SourceKey::tryFromIp($initiatorIp);
		if ($initiator !== null && $this->addresses->isIgnored($initiator)) {
			return;
		}
		$params = $this->settings->params(LoginFlowMismatch::ID);
		$now = $this->timeFactory->getTime();
		$age = max(0, $now - $startedAt);
		[$rule, $severity] = $this->evaluate($initiator, $granter, $age, (int)$params['max_age'], $now);
		if ($rule === null) {
			return;
		}
		$uid = $token->getUID();
		$trusted = $severity === Severity::Medium && $initiator !== null && $this->trustedNetworks->isTrusted($uid, $initiator);
		$draft = new DetectionDraft(
			checkId: LoginFlowMismatch::ID,
			source: $initiator ?? $granter,
			uid: $uid,
			tokenId: $token->getId(),
			facts: [
				'rule' => $rule,
				'initiator' => $initiator?->ip,
				'granter' => $granter->ip,
				'age' => $age,
				'startedAt' => $startedAt,
				'client' => Explanation::cleanUserAgent($token->getName()) ?? '',
				'tokenId' => $token->getId(),
				'trusted' => $trusted,
				'first' => $startedAt,
				'last' => $now,
			],
			severity: $trusted ? Severity::Low : $severity,
			userAgent: $userAgent,
		);
		$this->engine->handle($draft, $this->check->responsesFor($draft, $this->settings->responses(LoginFlowMismatch::ID), $params));
	}

	/**
	 * @return array{0: ?string, 1: Severity} the rule that applies (null for none) and its severity
	 */
	private function evaluate(?SourceKey $initiator, SourceKey $granter, int $age, int $maxAge, int $now): array {
		if ($initiator !== null) {
			if ($this->addressResolver->resolve($initiator)->isDenied($now)) {
				return [LoginFlowMismatch::RULE_INITIATOR_BLOCKED, Severity::High];
			}
			if ($this->flags->sourceFlag($initiator) !== null) {
				return [LoginFlowMismatch::RULE_INITIATOR_FLAGGED, Severity::High];
			}
			if ($initiator->family === $granter->family && !$initiator->sameNetwork($granter)) {
				return [LoginFlowMismatch::RULE_OTHER_NETWORK, Severity::Medium];
			}
		}
		if ($age > $maxAge) {
			return [LoginFlowMismatch::RULE_TOO_OLD, Severity::Medium];
		}
		if ($initiator !== null && $initiator->family !== $granter->family) {
			return [LoginFlowMismatch::RULE_OTHER_FAMILY, Severity::Low];
		}
		return [null, Severity::Low];
	}
}
