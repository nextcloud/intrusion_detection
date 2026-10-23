<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\KnownDevice;

use OCP\IConfig;
use OCP\IRequest;
use OCP\IURLGenerator;
use OCP\Security\ISecureRandom;

/**
 * The known-device cookie (concept section 11.5.1): a random device id of
 * ID_LENGTH characters from ISecureRandom, `HttpOnly`, `SameSite=Lax`,
 * for the web root. On HTTPS, or when the server is configured for it
 * (`forcessl`), it is `Secure` and its name carries the strictest prefix
 * browsers allow: `__Host-` for a server at the root of its host, else
 * `__Secure-`, so that no other site of the domain and no plain HTTP
 * response can set it. The id is the secret: only a keyed fingerprint of
 * it is stored, and it is never logged.
 */
class DeviceCookie {
	public const PREFIX = 'nc_ids_device_';
	public const ID_LENGTH = 43;
	private const ALPHABET = ISecureRandom::CHAR_ALPHANUMERIC . '-_';

	public function __construct(
		private readonly IRequest $request,
		private readonly IConfig $config,
		private readonly IURLGenerator $urlGenerator,
		private readonly ISecureRandom $random,
	) {
	}

	public function name(): string {
		$name = self::PREFIX . preg_replace('/[^a-z0-9]/i', '', $this->config->getSystemValueString('instanceid'));
		if (!$this->isSecure()) {
			return $name;
		}
		return ($this->urlGenerator->getWebroot() === '' ? '__Host-' : '__Secure-') . $name;
	}

	/**
	 * The device id the request carries, or null when it has none or its
	 * cookie is not one of ours.
	 */
	public function read(): ?string {
		$value = $this->request->getCookie($this->name());
		return is_string($value) && self::isValid($value) ? $value : null;
	}

	public function newId(): string {
		return $this->random->generate(self::ID_LENGTH, self::ALPHABET);
	}

	/**
	 * @return bool whether the cookie could be set (not after the response headers were sent)
	 */
	public function write(#[\SensitiveParameter] string $deviceId, int $expires): bool {
		return $this->send($deviceId, $expires);
	}

	public function clear(): bool {
		return $this->send('', 1);
	}

	public static function isValid(#[\SensitiveParameter] string $value): bool {
		return strlen($value) === self::ID_LENGTH && strspn($value, self::ALPHABET) === self::ID_LENGTH;
	}

	/**
	 * @return array{expires: int, path: string, secure: bool, httponly: true, samesite: 'Lax'}
	 */
	public function options(int $expires): array {
		$webroot = $this->urlGenerator->getWebroot();
		return [
			'expires' => $expires,
			'path' => $webroot === '' ? '/' : $webroot,
			'secure' => $this->isSecure(),
			'httponly' => true,
			'samesite' => 'Lax',
		];
	}

	private function isSecure(): bool {
		return $this->request->getServerProtocol() === 'https' || $this->config->getSystemValueBool('forcessl');
	}

	protected function send(#[\SensitiveParameter] string $value, int $expires): bool {
		if (headers_sent()) {
			return false;
		}
		return setcookie($this->name(), $value, $this->options($expires));
	}
}
