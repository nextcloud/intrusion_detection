<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Traps;

use OCA\IntrusionDetection\Check\Checks\ReservedName;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\DecoyMapper;
use OCP\AppFramework\Utility\ITimeFactory;

/**
 * Reserved names and decoy login names that have become accounts since,
 * for the setup check and the Decoys tab. Looking a name up costs two user
 * backend lookups (LDAP searches), so the result is stored: it is looked up
 * again when the names change and by the hourly status job, never when a
 * page or a setup check reads it.
 */
class TrapNameCollisions {
	public function __construct(
		private readonly Settings $settings,
		private readonly DecoyMapper $decoys,
		private readonly AccountNames $accounts,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * @return list<string> reserved names that are accounts
	 */
	public function reserved(): array {
		return $this->stored()['reserved'];
	}

	/**
	 * @return list<string> reserved names and decoy login names that are accounts, sorted
	 */
	public function all(): array {
		$stored = $this->stored();
		$names = array_values(array_unique(array_merge($stored['reserved'], $stored['decoys'])));
		sort($names);
		return $names;
	}

	/**
	 * Look every name up again and store the result.
	 *
	 * @return array{reserved: list<string>, decoys: list<string>, checkedAt: int}
	 */
	public function refresh(): array {
		$exists = fn (string $name): bool => $this->accounts->exists($name);
		$result = [
			'reserved' => array_values(array_filter($this->settings->paramList(ReservedName::ID, 'names'), $exists)),
			'decoys' => array_values(array_filter($this->decoys->loginNames(), $exists)),
			'checkedAt' => $this->timeFactory->getTime(),
		];
		$this->settings->setGlobal(GlobalSettings::TRAP_NAME_COLLISIONS, $result);
		return $result;
	}

	/**
	 * @return array{reserved: list<string>, decoys: list<string>, checkedAt: int}
	 */
	private function stored(): array {
		$stored = $this->settings->getJson(GlobalSettings::TRAP_NAME_COLLISIONS);
		if (!is_int($stored['checkedAt'] ?? null)) {
			return $this->refresh();
		}
		return [
			'reserved' => self::names($stored['reserved'] ?? null),
			'decoys' => self::names($stored['decoys'] ?? null),
			'checkedAt' => $stored['checkedAt'],
		];
	}

	/**
	 * @return list<string>
	 */
	private static function names(mixed $value): array {
		return is_array($value) ? array_values(array_filter($value, 'is_string')) : [];
	}
}
