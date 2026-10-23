<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\State;

use OCA\IntrusionDetection\AppInfo\Application;
use OCP\Config\ValueType;
use OCP\IAppConfig;

/**
 * The few small values of internal state that requests read often, kept in
 * the app config, which core holds in memory: a read costs no query. They
 * change rarely, because every app config write drops core's cached app
 * config. All other internal state is in {@see AppState}.
 */
class HotState {
	/** How many decoy credentials exist, so failed logins skip the lookup while there are none */
	public const DECOY_COUNT = 'decoy_count';
	/** Until when sessions with an unconfirmed login may exist, so that resumed sessions are checked */
	public const STEP_UP_SESSIONS_UNTIL = 'step_up_sessions_until';
	/** While in the future, low-value attempts are sampled because the attempts table is flooded */
	public const ATTEMPTS_FLOOD_UNTIL = 'attempts_flood_until';
	/** This server's own addresses seen in web requests, for cron and occ */
	public const SERVER_ADDRESSES = 'server_addresses';

	/** @var array<string, array{0: ValueType, 1: int|list<string>}> value type and default by key, for the config lexicon */
	public const LEXICON = [
		self::DECOY_COUNT => [ValueType::INT, 0],
		self::STEP_UP_SESSIONS_UNTIL => [ValueType::INT, 0],
		self::ATTEMPTS_FLOOD_UNTIL => [ValueType::INT, 0],
		self::SERVER_ADDRESSES => [ValueType::ARRAY, []],
	];

	public function __construct(
		private readonly IAppConfig $appConfig,
	) {
	}

	public function decoyCount(): int {
		return $this->getInt(self::DECOY_COUNT);
	}

	public function setDecoyCount(int $count): void {
		$this->setInt(self::DECOY_COUNT, $count);
	}

	public function stepUpSessionsUntil(): int {
		return $this->getInt(self::STEP_UP_SESSIONS_UNTIL);
	}

	public function setStepUpSessionsUntil(int $until): void {
		$this->setInt(self::STEP_UP_SESSIONS_UNTIL, $until);
	}

	public function attemptsFloodUntil(): int {
		return $this->getInt(self::ATTEMPTS_FLOOD_UNTIL);
	}

	public function setAttemptsFloodUntil(int $until): void {
		$this->setInt(self::ATTEMPTS_FLOOD_UNTIL, $until);
	}

	/**
	 * @return list<string>
	 */
	public function serverAddresses(): array {
		return array_values(array_filter($this->appConfig->getValueArray(Application::APP_ID, self::SERVER_ADDRESSES, []), 'is_string'));
	}

	/**
	 * @param list<string> $addresses
	 */
	public function setServerAddresses(array $addresses): void {
		$this->appConfig->setValueArray(Application::APP_ID, self::SERVER_ADDRESSES, $addresses);
	}

	private function getInt(string $key): int {
		return max(0, $this->appConfig->getValueInt(Application::APP_ID, $key, 0));
	}

	private function setInt(string $key, int $value): void {
		$this->appConfig->setValueInt(Application::APP_ID, $key, $value);
	}
}
