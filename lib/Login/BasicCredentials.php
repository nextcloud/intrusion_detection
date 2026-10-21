<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Login;

/**
 * The Basic credentials of the request, as PHP or core's
 * `OC::handleAuthHeaders()` put them into `$_SERVER`.
 *
 * Never read them through `IRequest::getHeader('PHP_AUTH_USER')`: that
 * also returns a client's own `PHP-Auth-User` header.
 */
final class BasicCredentials {
	/**
	 * @return array{string, string}|null the user name and the password; null when either is missing
	 */
	public static function fromServer(): ?array {
		$user = $_SERVER['PHP_AUTH_USER'] ?? '';
		$password = $_SERVER['PHP_AUTH_PW'] ?? '';
		return $user !== '' && $password !== '' ? [$user, $password] : null;
	}
}
