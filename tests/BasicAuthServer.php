<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests;

/**
 * Sets the Basic credentials that PHP and core put into `$_SERVER`, and
 * restores `$_SERVER` after each test.
 */
trait BasicAuthServer {
	/** @var array<string, mixed> */
	private array $savedBasicServer = [];

	#[\PHPUnit\Framework\Attributes\Before]
	protected function saveBasicServer(): void {
		$this->savedBasicServer = [];
		foreach (['PHP_AUTH_USER', 'PHP_AUTH_PW'] as $key) {
			if (array_key_exists($key, $_SERVER)) {
				$this->savedBasicServer[$key] = $_SERVER[$key];
			}
			unset($_SERVER[$key]);
		}
	}

	#[\PHPUnit\Framework\Attributes\After]
	protected function restoreBasicServer(): void {
		$this->setBasicCredentials(null, null);
		foreach ($this->savedBasicServer as $key => $value) {
			$_SERVER[$key] = $value;
		}
	}

	/**
	 * Basic credentials of the request; null removes them.
	 */
	protected function setBasicCredentials(?string $user, #[\SensitiveParameter] ?string $password): void {
		unset($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW']);
		if ($user !== null) {
			$_SERVER['PHP_AUTH_USER'] = $user;
		}
		if ($password !== null) {
			$_SERVER['PHP_AUTH_PW'] = $password;
		}
	}
}
