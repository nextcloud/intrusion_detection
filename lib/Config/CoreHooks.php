<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Config;

/**
 * The APIs of Nextcloud server the app hooks into that not every server
 * version has. Without one, the parts of the app that use it do nothing:
 * the checks that need it are unavailable, and a setup check and occ
 * intrusion:status name what is missing.
 *
 * Each hook is a class or interface that must exist, or a method of one.
 * The answers are kept for the request.
 */
class CoreHooks {
	public const REQUEST_GUARDS = 'request_guards';
	public const SHARE_ACCESS_EVENT = 'share_access_event';
	public const RESET_EVENT = 'reset_event';
	public const LOGIN_FLOW_EVENT = 'login_flow_event';
	public const APP_PASSWORD_EVENT = 'app_password_event';
	public const CHALLENGE_REQUESTER = 'challenge_requester';
	public const DAV_PLUGIN_EVENT = 'dav_plugin_event';

	/** @var array<string, list<string>> per hook, classes or "class::method" that must exist */
	public const HOOKS = [
		self::REQUEST_GUARDS => [
			'OCP\\Security\\Guard\\IRequestGuard',
			'OCP\\Security\\Guard\\GuardDecision',
			'OCP\\AppFramework\\Bootstrap\\IRegistrationContext::registerRequestGuard',
		],
		self::SHARE_ACCESS_EVENT => ['OCP\\Share\\Events\\ShareLinkAccessFailedEvent'],
		self::RESET_EVENT => ['OCP\\Security\\Events\\PasswordResetRequestedEvent'],
		self::LOGIN_FLOW_EVENT => ['OCP\\Authentication\\Events\\LoginFlowV2GrantedEvent'],
		self::APP_PASSWORD_EVENT => ['OCP\\Authentication\\Events\\AppPasswordCreatedEvent'],
		self::CHALLENGE_REQUESTER => ['OCP\\Authentication\\TwoFactorAuth\\IChallengeRequester'],
		self::DAV_PLUGIN_EVENT => ['OCA\\DAV\\Events\\SabrePluginAddEvent'],
	];

	/** @var array<string, bool> */
	private array $known = [];

	public function has(string $hook): bool {
		if (!isset($this->known[$hook])) {
			$this->known[$hook] = true;
			foreach (self::HOOKS[$hook] ?? [] as $name) {
				if (!$this->exists($name)) {
					$this->known[$hook] = false;
					break;
				}
			}
		}
		return $this->known[$hook];
	}

	/**
	 * @return list<string> the hooks this server does not have
	 */
	public function missing(): array {
		return array_values(array_filter(array_keys(self::HOOKS), fn (string $hook): bool => !$this->has($hook)));
	}

	protected function exists(string $name): bool {
		if (str_contains($name, '::')) {
			[$class, $method] = explode('::', $name, 2);
			return (class_exists($class) || interface_exists($class)) && method_exists($class, $method);
		}
		return class_exists($name) || interface_exists($name);
	}
}
