<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\WasThisYou;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\AccountUnderAttack;
use OCA\IntrusionDetection\Check\Checks\PasswordSpraying;
use OCA\IntrusionDetection\Check\Checks\SecondFactorFailed;
use OCA\IntrusionDetection\Check\Checks\StepUpFailed;
use OCA\IntrusionDetection\Check\Checks\StepUpRefused;
use OCA\IntrusionDetection\Check\Checks\StepUpRefusedClient;
use OCA\IntrusionDetection\Check\Checks\StepUpUnconfirmed;
use OCA\IntrusionDetection\Check\InvalidParamException;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Explain\IAsksWasThisYou;
use Psr\Container\ContainerInterface;

/**
 * Which detections ask their user "Was this you?" (concept section 11.8),
 * and what an answer involves.
 *
 * A detection asks when it is about an account and its check is listed in
 * ALWAYS, or the check implements {@see IAsksWasThisYou} and says so for
 * this detection.
 */
class Questions {
	/** Checks whose every detection about an account asks */
	public const ALWAYS = [SecondFactorFailed::ID, AccountUnderAttack::ID, 'token_concurrent_use'];

	/** Checks whose detections involve the account's password: "No" also requires a new one */
	public const PASSWORD_INVOLVED = [
		SecondFactorFailed::ID,
		PasswordSpraying::ID,
		StepUpFailed::ID,
		StepUpRefused::ID,
		StepUpRefusedClient::ID,
		StepUpUnconfirmed::ID,
	];

	public function __construct(
		private readonly CheckRegistry $registry,
		private readonly ContainerInterface $container,
	) {
	}

	public function asks(Detection $detection): bool {
		if ($detection->getUid() === null) {
			return false;
		}
		if (in_array($detection->getCheckId(), self::ALWAYS, true)) {
			return true;
		}
		try {
			$check = $this->container->get($this->registry->classOf($detection->getCheckId()));
		} catch (InvalidParamException) {
			return false;
		}
		return $check instanceof IAsksWasThisYou && $check->asksWasThisYou($detection);
	}

	/**
	 * Whether the detection still waits for its answer.
	 */
	public function isOpen(Detection $detection): bool {
		return $detection->getUserVerdict() === null && $this->asks($detection);
	}

	public function involvesPassword(Detection $detection): bool {
		return in_array($detection->getCheckId(), self::PASSWORD_INVOLVED, true);
	}

	/**
	 * The ids of the session tokens and app passwords a detection is about.
	 *
	 * @return list<int>
	 */
	public static function sessionTokens(Detection $detection): array {
		$facts = $detection->getExplanationData()['facts'] ?? [];
		if (!is_array($facts)) {
			return [];
		}
		$ids = is_array($facts['sessionTokenIds'] ?? null) ? $facts['sessionTokenIds'] : [];
		$ids[] = $facts['sessionTokenId'] ?? null;
		return array_values(array_unique(array_filter($ids, 'is_int')));
	}

	public static function tokenId(Detection $detection): ?int {
		$facts = $detection->getExplanationData()['facts'] ?? [];
		return is_array($facts) && is_int($facts['tokenId'] ?? null) ? $facts['tokenId'] : null;
	}
}
